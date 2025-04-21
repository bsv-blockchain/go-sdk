package clients

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"bytes"
	"fmt"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/auth/transports"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const (
	PaymentVersion = "1.0"
)

// SimplifiedFetchRequestOptions represents configuration options for HTTP requests.
type SimplifiedFetchRequestOptions struct {
	Method       string
	Headers      map[string]string
	Body         []byte
	RetryCounter *int
}

// AuthPeer represents an authenticated peer with potential certificate requests.
type AuthPeer struct {
	Peer                       *auth.Peer
	IdentityKey                string
	SupportsMutualAuth         *bool
	PendingCertificateRequests []bool
}

// AuthFetch provides a lightweight client for interacting with servers
// over a simplified HTTP transport mechanism. It integrates session management, peer communication,
// and certificate handling to enable secure and mutually-authenticated requests.
//
// Additionally, it automatically handles 402 Payment Required responses by creating
// and sending BSV payment transactions when necessary.
type AuthFetch struct {
	sessionManager        auth.SessionManager
	wallet                wallet.Interface
	callbacks             map[string]struct{ resolve, reject func(interface{}) }
	certificatesReceived  []*certificates.VerifiableCertificate
	requestedCertificates *utils.RequestedCertificateSet
	peers                 map[string]*AuthPeer
}

// New constructs a new AuthFetch instance.
func New(w wallet.Interface, requestedCerts *utils.RequestedCertificateSet, sessionMgr auth.SessionManager) *AuthFetch {
	if sessionMgr == nil {
		sessionMgr = auth.NewSessionManager()
	}

	return &AuthFetch{
		sessionManager:        sessionMgr,
		wallet:                w,
		callbacks:             make(map[string]struct{ resolve, reject func(interface{}) }),
		certificatesReceived:  []*certificates.VerifiableCertificate{},
		requestedCertificates: requestedCerts,
		peers:                 make(map[string]*AuthPeer),
	}
}

// Fetch mutually authenticates and sends a HTTP request to a server.
//
// 1) Attempt the request.
// 2) If 402 Payment Required, automatically create and send payment.
// 3) Return the final response.
func (a *AuthFetch) Fetch(ctx context.Context, urlStr string, config *SimplifiedFetchRequestOptions) (*http.Response, error) {
	if config == nil {
		config = &SimplifiedFetchRequestOptions{}
	}

	// Handle retry counter
	if config.RetryCounter != nil {
		if *config.RetryCounter <= 0 {
			return nil, errors.New("request failed after maximum number of retries")
		}
		counter := *config.RetryCounter - 1
		config.RetryCounter = &counter
	}

	// Create response channel
	responseChan := make(chan struct {
		resp *http.Response
		err  error
	})

	go func() {
		// Apply defaults
		method := config.Method
		if method == "" {
			method = "GET"
		}
		headers := config.Headers
		if headers == nil {
			headers = make(map[string]string)
		}
		body := config.Body

		// Extract a base URL
		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			responseChan <- struct {
				resp *http.Response
				err  error
			}{nil, fmt.Errorf("invalid URL: %w", err)}
			return
		}
		baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

		// Create a new transport for this base URL if needed
		var peerToUse *AuthPeer
		if _, exists := a.peers[baseURL]; !exists {
			// Create a peer for the request
			transport, err := transports.NewSimplifiedHTTPTransport(&transports.SimplifiedHTTPTransportOptions{
				BaseURL: baseURL,
			})
			if err != nil {
				responseChan <- struct {
					resp *http.Response
					err  error
				}{nil, fmt.Errorf("failed to create transport: %w", err)}
				return
			}

			peerOpts := &auth.PeerOptions{
				Wallet:                a.wallet,
				Transport:             transport,
				CertificatesToRequest: a.requestedCertificates,
				SessionManager:        a.sessionManager,
			}

			peerToUse = &AuthPeer{
				Peer:                       auth.NewPeer(peerOpts),
				PendingCertificateRequests: []bool{},
			}
			a.peers[baseURL] = peerToUse

			// Set up certificate received listener
			peerToUse.Peer.ListenForCertificatesReceived(func(senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
				a.certificatesReceived = append(a.certificatesReceived, certs...)
				return nil
			})

			// Set up certificate requested listener
			peerToUse.Peer.ListenForCertificatesRequested(func(verifier *ec.PublicKey, requestedCertificates utils.RequestedCertificateSet) error {
				a.peers[baseURL].PendingCertificateRequests = append(a.peers[baseURL].PendingCertificateRequests, true)

				certificatesToInclude, err := utils.GetVerifiableCertificates(
					a.wallet,
					requestedCertificates,
					verifier,
				)
				if err != nil {
					return err
				}

				err = a.peers[baseURL].Peer.SendCertificateResponse(verifier, certificatesToInclude)
				if err != nil {
					return err
				}

				// Give the backend time to process certificates
				go func() {
					time.Sleep(500 * time.Millisecond)
					if len(a.peers[baseURL].PendingCertificateRequests) > 0 {
						a.peers[baseURL].PendingCertificateRequests = a.peers[baseURL].PendingCertificateRequests[1:]
					}
				}()
				return nil
			})
		} else {
			// Check if there's a session associated with this baseURL
			supportsMutualAuth := a.peers[baseURL].SupportsMutualAuth
			if supportsMutualAuth != nil && !*supportsMutualAuth {
				// Use standard fetch if mutual authentication is not supported
				resp, err := a.handleFetchAndValidate(urlStr, config, a.peers[baseURL])
				responseChan <- struct {
					resp *http.Response
					err  error
				}{resp, err}
				return
			}
			peerToUse = a.peers[baseURL]
		}

		// Generate request nonce
		requestNonce := make([]byte, 32)
		if _, err := rand.Read(requestNonce); err != nil {
			responseChan <- struct {
				resp *http.Response
				err  error
			}{nil, fmt.Errorf("failed to generate nonce: %w", err)}
			return
		}
		requestNonceBase64 := base64.StdEncoding.EncodeToString(requestNonce)

		// Serialize the simplified fetch request
		requestData, err := a.serializeRequest(method, headers, body, parsedURL, requestNonce)
		if err != nil {
			responseChan <- struct {
				resp *http.Response
				err  error
			}{nil, fmt.Errorf("failed to serialize request: %w", err)}
			return
		}

		// Setup callback for this request
		a.callbacks[requestNonceBase64] = struct {
			resolve func(interface{})
			reject  func(interface{})
		}{
			resolve: func(resp interface{}) {
				if httpResp, ok := resp.(*http.Response); ok {
					responseChan <- struct {
						resp *http.Response
						err  error
					}{httpResp, nil}
				} else {
					responseChan <- struct {
						resp *http.Response
						err  error
					}{nil, fmt.Errorf("invalid response type")}
				}
			},
			reject: func(err interface{}) {
				if errStr, ok := err.(string); ok {
					responseChan <- struct {
						resp *http.Response
						err  error
					}{nil, errors.New(errStr)}
				} else if errObj, ok := err.(error); ok {
					responseChan <- struct {
						resp *http.Response
						err  error
					}{nil, errObj}
				} else {
					responseChan <- struct {
						resp *http.Response
						err  error
					}{nil, fmt.Errorf("%v", err)}
				}
			},
		}

		// Set up listener for response
		var listenerID int
		listenerID = peerToUse.Peer.ListenForGeneralMessages(func(senderPublicKey *ec.PublicKey, payload []byte) error {
			// Create a reader
			responseReader := util.NewReader(payload)

			// Deserialize first 32 bytes of payload (response nonce)
			responseNonce, err := responseReader.ReadBytes(32)
			if err != nil {
				return fmt.Errorf("failed to read response nonce: %w", err)
			}

			responseNonceBase64 := base64.StdEncoding.EncodeToString(responseNonce)
			if responseNonceBase64 != requestNonceBase64 {
				return nil // Not our response
			}

			// Stop listening once we got our response
			peerToUse.Peer.StopListeningForGeneralMessages(listenerID)

			// Save the identity key for the peer
			if senderPublicKey != nil {
				a.peers[baseURL].IdentityKey = senderPublicKey.ToDERHex()
				supportsMutualAuth := true
				a.peers[baseURL].SupportsMutualAuth = &supportsMutualAuth
			}

			// Read status code
			statusCode, err := responseReader.ReadVarInt32()
			if err != nil {
				return fmt.Errorf("failed to read status code: %w", err)
			}

			// Read headers
			responseHeaders := make(http.Header)
			nHeaders, err := responseReader.ReadVarInt32()
			if err != nil {
				return fmt.Errorf("failed to read header count: %w", err)
			}

			for i := uint32(0); i < nHeaders; i++ {
				// Read header key
				headerKey, err := responseReader.ReadString()
				if err != nil {
					return fmt.Errorf("failed to read header key: %w", err)
				}

				// Read header value
				headerValue, err := responseReader.ReadString()
				if err != nil {
					return fmt.Errorf("failed to read header value: %w", err)
				}

				responseHeaders.Add(headerKey, headerValue)
			}

			// Add back server identity key header
			if senderPublicKey != nil {
				responseHeaders.Add("x-bsv-auth-identity-key", senderPublicKey.ToDERHex())
			}

			// Read body
			var responseBody []byte
			bodyLen, err := responseReader.ReadVarInt32()
			if err != nil {
				return fmt.Errorf("failed to read body length: %w", err)
			}

			if bodyLen > 0 {
				responseBody, err = responseReader.ReadBytes(int(bodyLen))
				if err != nil {
					return fmt.Errorf("failed to read body: %w", err)
				}
			}

			// Create response object
			response := &http.Response{
				StatusCode: int(statusCode),
				Status:     fmt.Sprintf("%d", statusCode),
				Header:     responseHeaders,
				Body:       io.NopCloser(bytes.NewReader(responseBody)),
			}

			// Resolve with the response
			if callback, ok := a.callbacks[requestNonceBase64]; ok {
				callback.resolve(response)
				delete(a.callbacks, requestNonceBase64)
			}

			return nil
		})

		// Make sure no certificate requests are pending
		if len(peerToUse.PendingCertificateRequests) > 0 {
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()

			done := make(chan bool)
			go func() {
				for {
					select {
					case <-done:
						return
					case <-ticker.C:
						if len(peerToUse.PendingCertificateRequests) == 0 {
							done <- true
							return
						}
					}
				}
			}()

			<-done
		}

		// Send the request
		identityKey := a.peers[baseURL].IdentityKey
		var idKeyObject *ec.PublicKey
		var toPublicKeyError error
		if identityKey != "" {
			idKeyObject, toPublicKeyError = ec.PublicKeyFromString(identityKey)
			if toPublicKeyError != nil {
				idKeyObject = nil // Reset if there was an error
			}
		}

		err = peerToUse.Peer.ToPeer(requestData, idKeyObject, 30000) // 30 second timeout
		if err != nil {
			if strings.Contains(err.Error(), "Session not found for nonce") {
				// Session expired, retry with a new session
				delete(a.peers, baseURL)

				// Set up retry counter if not set
				if config.RetryCounter == nil {
					retryCount := 3
					config.RetryCounter = &retryCount
				}

				// Retry the request
				resp, retryErr := a.Fetch(ctx, urlStr, config)
				responseChan <- struct {
					resp *http.Response
					err  error
				}{resp, retryErr}
				return
			} else if strings.Contains(err.Error(), "HTTP server failed to authenticate") {
				// Fall back to regular HTTP request
				resp, fallbackErr := a.handleFetchAndValidate(urlStr, config, peerToUse)
				responseChan <- struct {
					resp *http.Response
					err  error
				}{resp, fallbackErr}
				return
			} else {
				responseChan <- struct {
					resp *http.Response
					err  error
				}{nil, err}
				return
			}
		}
	}()

	// Wait for the response or context cancellation
	select {
	case result := <-responseChan:
		if result.err != nil {
			return nil, result.err
		}

		// Check if server requires payment
		if result.resp.StatusCode == 402 {
			// Create and attach payment, then retry
			return a.handlePaymentAndRetry(ctx, urlStr, config, result.resp)
		}

		return result.resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// SendCertificateRequest requests Certificates from a Peer
func (a *AuthFetch) SendCertificateRequest(ctx context.Context, baseURL string, certificatesToRequest *utils.RequestedCertificateSet) ([]certificates.VerifiableCertificate, error) {
	// Implementation will go here
	return nil, nil
}

// ConsumeReceivedCertificates returns any certificates collected thus far, then clears them out.
func (a *AuthFetch) ConsumeReceivedCertificates() []*certificates.VerifiableCertificate {
	certs := a.certificatesReceived
	a.certificatesReceived = []*certificates.VerifiableCertificate{}
	return certs
}

// serializeRequest serializes the HTTP request to be sent over the Transport.
func (a *AuthFetch) serializeRequest(method string, headers map[string]string, body []byte, parsedURL *url.URL, requestNonce []byte) ([]byte, error) {
	// Implementation will go here
	return nil, nil
}

// handleFetchAndValidate handles a non-authenticated fetch requests and validates that the server is not claiming to be authenticated.
func (a *AuthFetch) handleFetchAndValidate(urlStr string, config *SimplifiedFetchRequestOptions, peerToUse *AuthPeer) (*http.Response, error) {
	// Implementation will go here
	return nil, nil
}

// handlePaymentAndRetry builds a transaction via wallet.CreateAction() and re-attempts the request with an x-bsv-payment header
// if we get 402 Payment Required.
func (a *AuthFetch) handlePaymentAndRetry(ctx context.Context, urlStr string, config *SimplifiedFetchRequestOptions, originalResponse *http.Response) (*http.Response, error) {
	// Implementation will go here
	return nil, nil
}
