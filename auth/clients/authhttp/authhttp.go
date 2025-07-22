package clients

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
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
	logger                *log.Logger // Logger for debug/warning messages
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
		logger:                log.New(log.Writer(), "[AuthHTTP] ", log.LstdFlags),
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
					ctx,
					&utils.GetVerifiableCertificatesOptions{
						Wallet:                a.wallet,
						RequestedCertificates: &requestedCertificates,
						VerifierIdentityKey:   verifier,
					},
				)
				if err != nil {
					return err
				}

				err = a.peers[baseURL].Peer.SendCertificateResponse(ctx, verifier, certificatesToInclude)
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

		err = peerToUse.Peer.ToPeer(ctx, requestData, idKeyObject, 30000) // 30 second timeout
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
func (a *AuthFetch) SendCertificateRequest(ctx context.Context, baseURL string, certificatesToRequest *utils.RequestedCertificateSet) ([]*certificates.VerifiableCertificate, error) {
	// Parse the URL to get the base URL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	baseURLStr := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// Get or create a peer for this base URL
	var peerToUse *AuthPeer
	if peer, exists := a.peers[baseURLStr]; exists {
		peerToUse = peer
	} else {
		// Create a new transport for this base URL
		transport, err := transports.NewSimplifiedHTTPTransport(&transports.SimplifiedHTTPTransportOptions{
			BaseURL: baseURLStr,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create transport: %w", err)
		}

		// Create a new peer with the transport
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
		a.peers[baseURLStr] = peerToUse
	}

	// Create a channel for waiting for certificates
	certChan := make(chan struct {
		certs []*certificates.VerifiableCertificate
		err   error
	})

	// Set up certificate received listener
	var callbackID int
	callbackID = peerToUse.Peer.ListenForCertificatesReceived(func(senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
		peerToUse.Peer.StopListeningForCertificatesReceived(callbackID)
		a.certificatesReceived = append(a.certificatesReceived, certs...)
		certChan <- struct {
			certs []*certificates.VerifiableCertificate
			err   error
		}{certs, nil}
		return nil
	})

	// Get peer identity key if available
	var identityKey *ec.PublicKey
	if peerToUse.IdentityKey != "" {
		pubKey, err := ec.PublicKeyFromString(peerToUse.IdentityKey)
		if err == nil {
			identityKey = pubKey
		}
	}

	// Request certificates
	go func() {
		err := peerToUse.Peer.RequestCertificates(ctx, identityKey, *certificatesToRequest, 30000) // 30 second timeout
		if err != nil {
			peerToUse.Peer.StopListeningForCertificatesReceived(callbackID)
			certChan <- struct {
				certs []*certificates.VerifiableCertificate
				err   error
			}{nil, err}
		}
	}()

	// Wait for response or context cancellation
	select {
	case result := <-certChan:
		return result.certs, result.err
	case <-ctx.Done():
		peerToUse.Peer.StopListeningForCertificatesReceived(callbackID)
		return nil, ctx.Err()
	}
}

// ConsumeReceivedCertificates returns any certificates collected thus far, then clears them out.
func (a *AuthFetch) ConsumeReceivedCertificates() []*certificates.VerifiableCertificate {
	certs := a.certificatesReceived
	a.certificatesReceived = []*certificates.VerifiableCertificate{}
	return certs
}

// serializeRequest serializes the HTTP request to be sent over the Transport.
func (a *AuthFetch) serializeRequest(method string, headers map[string]string, body []byte, parsedURL *url.URL, requestNonce []byte) ([]byte, error) {
	writer := util.NewWriter()

	// Write request nonce
	writer.WriteBytes(requestNonce)

	// Write method
	writer.WriteString(method)

	// Handle pathname (e.g. /path/to/resource)
	writer.WriteOptionalString(parsedURL.Path)

	// Handle search params (e.g. ?q=hello)
	searchParams := parsedURL.RawQuery
	if searchParams != "" {
		// auth client is using query string with leading "?", so the middleware need to include that character also.
		searchParams = "?" + searchParams
	}
	writer.WriteOptionalString(searchParams)

	// Construct headers to send / sign:
	// - Include custom headers prefixed with x-bsv (excluding those starting with x-bsv-auth)
	// - Include a normalized version of the content-type header
	// - Include the authorization header
	includedHeaders := [][]string{}
	for k, v := range headers {
		headerKey := strings.ToLower(k) // Always sign lower-case header keys
		if strings.HasPrefix(headerKey, "x-bsv-") || headerKey == "authorization" {
			if strings.HasPrefix(headerKey, "x-bsv-auth") {
				return nil, errors.New("no BSV auth headers allowed here")
			}
			includedHeaders = append(includedHeaders, []string{strings.ToLower(headerKey), v})
		} else if strings.HasPrefix(headerKey, "content-type") {
			// Normalize the Content-Type header by removing any parameters (e.g., "; charset=utf-8")
			contentType := strings.Split(v, ";")[0]
			includedHeaders = append(includedHeaders, []string{headerKey, strings.TrimSpace(contentType)})
		} else {
			// In Go we're more tolerant of headers, but log a warning
			a.logger.Printf("Warning: Unsupported header in simplified fetch: %s", k)
		}
	}

	// Sort the headers by key to ensure a consistent order for signing and verification
	sort.Slice(includedHeaders, func(i, j int) bool {
		return includedHeaders[i][0] < includedHeaders[j][0]
	})

	// Write number of headers
	writer.WriteVarInt(uint64(len(includedHeaders)))

	// Write each header
	for _, header := range includedHeaders {
		// Write header key
		writer.WriteString(header[0])
		// Write header value
		writer.WriteString(header[1])
	}

	// If method typically carries a body and body is empty, default it
	methodsThatTypicallyHaveBody := []string{"POST", "PUT", "PATCH", "DELETE"}
	if len(body) == 0 && contains(methodsThatTypicallyHaveBody, strings.ToUpper(method)) {
		// Check if content-type is application/json
		for _, header := range includedHeaders {
			if header[0] == "content-type" && strings.Contains(header[1], "application/json") {
				body = []byte("{}")
				break
			}
		}

		// If still empty and not JSON, use empty string
		if len(body) == 0 {
			body = []byte("")
		}
	}

	// Write body
	writer.WriteIntBytesOptional(body)

	return writer.Buf, nil
}

// contains checks if a string is present in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// handleFetchAndValidate handles a non-authenticated fetch requests and validates that the server is not claiming to be authenticated.
func (a *AuthFetch) handleFetchAndValidate(urlStr string, config *SimplifiedFetchRequestOptions, peerToUse *AuthPeer) (*http.Response, error) {
	// Create HTTP client
	client := &http.Client{}

	// Create request
	var reqBody io.Reader
	if len(config.Body) > 0 {
		reqBody = bytes.NewReader(config.Body)
	}

	req, err := http.NewRequest(config.Method, urlStr, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers
	for k, v := range config.Headers {
		req.Header.Add(k, v)
	}

	// Send request
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	// Validate that the server is not trying to fake authentication
	for k := range response.Header {
		if strings.ToLower(k) == "x-bsv-auth-identity-key" || strings.HasPrefix(strings.ToLower(k), "x-bsv-auth") {
			return nil, errors.New("the server is trying to claim it has been authenticated when it has not")
		}
	}

	// Set supportsMutualAuth to false if successful
	if response.StatusCode < 400 {
		supportsMutualAuth := false
		peerToUse.SupportsMutualAuth = &supportsMutualAuth
		return response, nil
	}

	return nil, fmt.Errorf("request failed with status: %d", response.StatusCode)
}

// handlePaymentAndRetry builds a transaction via wallet.CreateAction() and re-attempts the request with an x-bsv-payment header
// if we get 402 Payment Required.
func (a *AuthFetch) handlePaymentAndRetry(ctx context.Context, urlStr string, config *SimplifiedFetchRequestOptions, originalResponse *http.Response) (*http.Response, error) {
	// Make sure the server is using the correct payment version
	paymentVersion := originalResponse.Header.Get("x-bsv-payment-version")
	if paymentVersion == "" || paymentVersion != PaymentVersion {
		return nil, fmt.Errorf("unsupported x-bsv-payment-version response header. Client version: %s, Server version: %s",
			PaymentVersion, paymentVersion)
	}

	// Get required headers from the 402 response
	satoshisRequiredHeader := originalResponse.Header.Get("x-bsv-payment-satoshis-required")
	if satoshisRequiredHeader == "" {
		return nil, errors.New("missing x-bsv-payment-satoshis-required response header")
	}

	satoshisRequired, err := strconv.ParseUint(satoshisRequiredHeader, 10, 64)
	if err != nil || satoshisRequired <= 0 {
		return nil, errors.New("invalid x-bsv-payment-satoshis-required response header value")
	}

	serverIdentityKey := originalResponse.Header.Get("x-bsv-auth-identity-key")
	if serverIdentityKey == "" {
		return nil, errors.New("missing x-bsv-auth-identity-key response header")
	}

	derivationPrefix := originalResponse.Header.Get("x-bsv-payment-derivation-prefix")
	if derivationPrefix == "" {
		return nil, errors.New("missing x-bsv-payment-derivation-prefix response header")
	}

	// Create a random suffix for the derivation path
	nonceResult, err := utils.CreateNonce(ctx, a.wallet, wallet.Counterparty{
		Type: wallet.CounterpartyTypeSelf,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create derivation suffix: %w", err)
	}
	derivationSuffix := nonceResult

	// Convert server identity key to PublicKey object
	serverPubKey, err := ec.PublicKeyFromString(serverIdentityKey)
	if err != nil {
		return nil, fmt.Errorf("invalid server identity key: %w", err)
	}

	// Derive the public key for payment
	derivedKey, err := a.wallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: 2,
				Protocol:      "3241645161d8", // wallet payment protocol
			},
			KeyID: fmt.Sprintf("%s %s", derivationPrefix, derivationSuffix),
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: serverPubKey,
			},
		},
	}, "auth-payment")

	if err != nil {
		return nil, fmt.Errorf("failed to derive payment key: %w", err)
	}

	// Use the wallet to create a P2PKH locking script from the derived key
	// The wallet will handle the conversion of public key to address and script generation
	randomizeOutputs := false
	actionResult, err := a.wallet.CreateAction(ctx, wallet.CreateActionArgs{
		Description: fmt.Sprintf("Payment for request to %s", urlStr),
		Outputs: []wallet.CreateActionOutput{
			{
				Satoshis:      satoshisRequired,
				LockingScript: derivedKey.PublicKey.ToDER(),
				CustomInstructions: fmt.Sprintf(`{"derivationPrefix":"%s","derivationSuffix":"%s","payee":"%s"}`,
					derivationPrefix, derivationSuffix, serverIdentityKey),
				OutputDescription: "HTTP request payment",
			},
		},
		Options: &wallet.CreateActionOptions{
			RandomizeOutputs: &randomizeOutputs,
		},
	}, "auth-payment")

	if err != nil {
		return nil, fmt.Errorf("failed to create payment transaction: %w", err)
	}

	// Attach payment info to request headers
	paymentInfo := map[string]interface{}{
		"derivationPrefix": derivationPrefix,
		"derivationSuffix": derivationSuffix,
		"transaction":      base64.StdEncoding.EncodeToString(actionResult.Tx),
	}

	paymentInfoJSON, err := json.Marshal(paymentInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize payment info: %w", err)
	}

	if config.Headers == nil {
		config.Headers = make(map[string]string)
	}
	config.Headers["x-bsv-payment"] = string(paymentInfoJSON)

	// Set up retry counter if not set
	if config.RetryCounter == nil {
		retryCount := 3
		config.RetryCounter = &retryCount
	}

	// Re-attempt request with payment attached
	return a.Fetch(ctx, urlStr, config)
}
