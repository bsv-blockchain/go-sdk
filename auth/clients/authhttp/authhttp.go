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
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/authpayload"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/auth/transports"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
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

// AuthFetchOptions provides configuration options for AuthFetch.
type AuthFetchOptions struct {
	CertificatesToRequest *utils.RequestedCertificateSet
	SessionManager        auth.SessionManager
	Logger                *slog.Logger
	HttpClient            *http.Client
}

// WithCertificatesToRequest sets the CertificatesToRequest with the provided certificate set.
// Those certificates will be requested on the handshake with any server.
// CertificatesToRequest argument cannot be nil.
func WithCertificatesToRequest(certificatesToRequest *utils.RequestedCertificateSet) func(*AuthFetchOptions) {
	if certificatesToRequest == nil {
		panic("certificatesToRequest must be provided in WithCertificatesToRequest")
	}
	return func(opts *AuthFetchOptions) {
		opts.CertificatesToRequest = certificatesToRequest
	}
}

// WithSessionManager sets a custom session manager for AuthFetch.
// sessionManager argument cannot be nil.
func WithSessionManager(sessionManager auth.SessionManager) func(*AuthFetchOptions) {
	if sessionManager == nil {
		panic("sessionManager cannot be set to nil")
	}
	return func(opts *AuthFetchOptions) {
		opts.SessionManager = sessionManager
	}
}

// WithLogger sets provided logger for AuthFetch.
// Logger cannot be nil.
// To prevent AuthFetch from logging, use WithoutLogging or simply pass a logger with slog.DiscardHandler.
func WithLogger(logger *slog.Logger) func(*AuthFetchOptions) {
	if logger == nil {
		panic("logger cannot be set to nil")
	}
	return func(opts *AuthFetchOptions) {
		opts.Logger = logger
	}
}

// WithoutLogging disables logging by assigning a no-op logger to the AuthFetch.
func WithoutLogging() func(*AuthFetchOptions) {
	return func(opts *AuthFetchOptions) {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
}

// WithHttpClient sets a custom HTTP client for AuthFetch.
// Useful if you have preconfigured HttpClient, or want to reuse a single HttpClient for all operations.
// Provided client cannot be nil.
func WithHttpClient(httpClient *http.Client) func(*AuthFetchOptions) {
	if httpClient == nil {
		panic("httpClient cannot be set to nil")
	}
	return func(opts *AuthFetchOptions) {
		opts.HttpClient = httpClient
	}
}

// WithHttpClientTransport sets a custom HTTP Transport on the HttpClient in AuthFetch.
// Useful for testing purposes.
// Provided transport cannot be nil.
//
// WARNING: It will override a transport in configured HttpClient - use with caution.
func WithHttpClientTransport(transport http.RoundTripper) func(*AuthFetchOptions) {
	if transport == nil {
		panic("roundTripper cannot be set to nil")
	}
	return func(opts *AuthFetchOptions) {
		if opts.HttpClient == nil {
			opts.HttpClient = &http.Client{}
		}
		opts.HttpClient.Transport = transport
	}
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
	logger                *slog.Logger // Logger for debug/warning messages
	client                *http.Client
	mu                    sync.RWMutex // Protects callbacks, peers, and certificatesReceived
}

// New constructs a new AuthFetch instance.
func New(w wallet.Interface, opts ...func(*AuthFetchOptions)) *AuthFetch {
	if w == nil {
		panic("wallet cannot be nil")
	}

	options := &AuthFetchOptions{
		SessionManager: auth.NewSessionManager(),
		HttpClient:     &http.Client{},
		Logger:         slog.Default(),
	}

	for _, opt := range opts {
		opt(options)
	}

	logger := options.Logger.With("component", "AuthFetch")

	return &AuthFetch{
		logger:                logger,
		wallet:                w,
		sessionManager:        options.SessionManager,
		requestedCertificates: options.CertificatesToRequest,
		callbacks:             make(map[string]struct{ resolve, reject func(interface{}) }),
		certificatesReceived:  []*certificates.VerifiableCertificate{},
		peers:                 make(map[string]*AuthPeer),
		client:                options.HttpClient,
	}
}

// Deprecated: SetLogger is deprecated; pass logger to New(..., logger) instead.
func (a *AuthFetch) SetLogger(logger *slog.Logger) { a.logger = logger }

// Fetch mutually authenticates and sends a HTTP request to a server.
//
// 1) Attempt the request.
// 2) If 402 Payment Required, automatically create and send payment.
// 3) Return the final response.
func (a *AuthFetch) Fetch(ctx context.Context, urlStr string, config *SimplifiedFetchRequestOptions) (*http.Response, error) {
	if config == nil {
		config = &SimplifiedFetchRequestOptions{}
	}
	if config.Method == "" {
		config.Method = "GET"
	}

	// validate headers
	for key := range config.Headers {
		if !authpayload.IsHeaderToIncludeInRequest(key) {
			return nil, fmt.Errorf("header %s is not allowed in auth fetch", key)
		}
	}

	// Handle retry counter
	if config.RetryCounter != nil {
		if *config.RetryCounter <= 0 {
			return nil, errors.New("request failed after maximum number of retries")
		}
		counter := *config.RetryCounter - 1
		config.RetryCounter = &counter
	}

	req, err := http.NewRequestWithContext(ctx, config.Method, urlStr, bytes.NewReader(config.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	for key, value := range config.Headers {
		req.Header.Set(key, value)
	}

	// Create response channel
	responseChan := make(chan struct {
		resp *http.Response
		err  error
	})

	go func() {
		baseURL := fmt.Sprintf("%s://%s", req.URL.Scheme, req.URL.Host)

		// Create new transport for this base URL if needed
		peerToUse, isNew, err := a.GetOrCreatePeer(baseURL, func() (*AuthPeer, error) {
			transport, err := transports.NewSimplifiedHTTPTransport(&transports.SimplifiedHTTPTransportOptions{
				BaseURL: baseURL,
				Client:  a.client,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create transport: %w", err)
			}

			peerOpts := &auth.PeerOptions{
				Wallet:                a.wallet,
				Transport:             transport,
				CertificatesToRequest: a.requestedCertificates,
				SessionManager:        a.sessionManager,
				Logger:                a.logger,
			}

			return &AuthPeer{
				Peer:                       auth.NewPeer(peerOpts),
				PendingCertificateRequests: []bool{},
			}, nil
		})
		if err != nil {
			responseChan <- struct {
				resp *http.Response
				err  error
			}{nil, err}
			return
		}

		if isNew {
			// Set up certificate received listener
			peerToUse.Peer.ListenForCertificatesReceived(func(_ context.Context, senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
				a.AppendCertificatesReceived(certs...)
				return nil
			})

			// Set up certificate requested listener
			peerToUse.Peer.ListenForCertificatesRequested(func(_ context.Context, verifier *ec.PublicKey, requestedCertificates utils.RequestedCertificateSet) error {
				a.AddPendingCertificateRequest(baseURL)

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

				peer := a.GetPeer(baseURL)
				if peer != nil {
					err = peer.Peer.SendCertificateResponse(ctx, verifier, certificatesToInclude)
					if err != nil {
						return err
					}
				}

				// Give the backend time to process certificates
				go func() {
					time.Sleep(500 * time.Millisecond)
					a.RemovePendingCertificateRequest(baseURL)
				}()
				return nil
			})
		} else {
			// Check if there's a session associated with this baseURL
			supportsMutualAuth := a.GetPeerSupportsMutualAuth(baseURL)
			if supportsMutualAuth != nil && !*supportsMutualAuth {
				// Use standard fetch if mutual authentication is not supported
				resp, err := a.handleFetchAndValidate(urlStr, config, peerToUse)
				responseChan <- struct {
					resp *http.Response
					err  error
				}{resp, err}
				return
			}
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
		requestData, err := authpayload.FromHTTPRequest(requestNonce, req)
		if err != nil {
			responseChan <- struct {
				resp *http.Response
				err  error
			}{nil, fmt.Errorf("failed to serialize request: %w", err)}
			return
		}

		// Setup callback for this request
		a.SetCallback(requestNonceBase64,
			func(resp interface{}) {
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
			func(err interface{}) {
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
		)

		// Set up listener for response
		var listenerID int32
		listenerID = peerToUse.Peer.ListenForGeneralMessages(func(_ context.Context, senderPublicKey *ec.PublicKey, payload []byte) error {
			peerToUse.Peer.StopListeningForGeneralMessages(listenerID)

			if senderPublicKey != nil {
				a.UpdatePeerIdentity(baseURL, senderPublicKey.ToDERHex(), true)
			}

			requestIDFromResponse, response, err := authpayload.ToHTTPResponse(payload, authpayload.WithSenderPublicKey(senderPublicKey))
			if err != nil {
				return fmt.Errorf("invalid response send by server: %w", err)
			}

			responseNonceBase64 := base64.StdEncoding.EncodeToString(requestIDFromResponse)
			if responseNonceBase64 != requestNonceBase64 {
				return nil // Not our response
			}

			// Resolve with the response
			a.InvokeCallback(requestNonceBase64, response)

			return nil
		})

		// Make sure no certificate requests are pending
		if a.HasPendingCertificateRequests(baseURL) {
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()

			for {
				<-ticker.C
				if !a.HasPendingCertificateRequests(baseURL) {
					break
				}
			}
		}

		// Send the request
		identityKey := a.GetPeerIdentityKey(baseURL)
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
				a.DeletePeer(baseURL)

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
			} else if errors.Is(err, transports.ErrHTTPServerFailedToAuthenticate) {
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
	peerToUse, _, err := a.GetOrCreatePeer(baseURLStr, func() (*AuthPeer, error) {
		transport, err := transports.NewSimplifiedHTTPTransport(&transports.SimplifiedHTTPTransportOptions{
			BaseURL: baseURLStr,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create transport: %w", err)
		}

		peerOpts := &auth.PeerOptions{
			Wallet:                a.wallet,
			Transport:             transport,
			CertificatesToRequest: a.requestedCertificates,
			SessionManager:        a.sessionManager,
		}

		return &AuthPeer{
			Peer:                       auth.NewPeer(peerOpts),
			PendingCertificateRequests: []bool{},
		}, nil
	})
	if err != nil {
		return nil, err
	}

	// Create a channel for waiting for certificates
	certChan := make(chan struct {
		certs []*certificates.VerifiableCertificate
		err   error
	})

	// Set up certificate received listener
	var callbackID int32
	callbackID = peerToUse.Peer.ListenForCertificatesReceived(func(_ context.Context, senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
		peerToUse.Peer.StopListeningForCertificatesReceived(callbackID)
		a.AppendCertificatesReceived(certs...)
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
	a.mu.Lock()
	defer a.mu.Unlock()
	certs := a.certificatesReceived
	a.certificatesReceived = []*certificates.VerifiableCertificate{}
	return certs
}

// GetPeer returns the AuthPeer for the given base URL, or nil if not found.
func (a *AuthFetch) GetPeer(baseURL string) *AuthPeer {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.peers[baseURL]
}

// SetPeer sets the AuthPeer for the given base URL.
func (a *AuthFetch) SetPeer(baseURL string, peer *AuthPeer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.peers[baseURL] = peer
}

// DeletePeer removes the AuthPeer for the given base URL.
func (a *AuthFetch) DeletePeer(baseURL string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.peers, baseURL)
}

// GetCallback returns the callback for the given nonce, or nil if not found.
func (a *AuthFetch) GetCallback(nonce string) (resolve, reject func(interface{}), exists bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	cb, ok := a.callbacks[nonce]
	if !ok {
		return nil, nil, false
	}
	return cb.resolve, cb.reject, true
}

// SetCallback sets the callback for the given nonce.
func (a *AuthFetch) SetCallback(nonce string, resolve, reject func(interface{})) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.callbacks[nonce] = struct{ resolve, reject func(interface{}) }{resolve, reject}
}

// DeleteCallback removes the callback for the given nonce.
func (a *AuthFetch) DeleteCallback(nonce string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.callbacks, nonce)
}

// AppendCertificatesReceived appends certificates to the received list.
func (a *AuthFetch) AppendCertificatesReceived(certs ...*certificates.VerifiableCertificate) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.certificatesReceived = append(a.certificatesReceived, certs...)
}

// GetOrCreatePeer atomically gets an existing peer or creates a new one using the provided function.
// Returns the peer and whether it was newly created.
func (a *AuthFetch) GetOrCreatePeer(baseURL string, createFn func() (*AuthPeer, error)) (*AuthPeer, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if peer, exists := a.peers[baseURL]; exists {
		return peer, false, nil
	}
	peer, err := createFn()
	if err != nil {
		return nil, false, err
	}
	a.peers[baseURL] = peer
	return peer, true, nil
}

// UpdatePeerIdentity updates the identity key and mutual auth support for a peer.
func (a *AuthFetch) UpdatePeerIdentity(baseURL string, identityKey string, supportsMutualAuth bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if peer, exists := a.peers[baseURL]; exists {
		peer.IdentityKey = identityKey
		peer.SupportsMutualAuth = &supportsMutualAuth
	}
}

// GetPeerIdentityKey returns the identity key for the given peer.
func (a *AuthFetch) GetPeerIdentityKey(baseURL string) string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if peer, exists := a.peers[baseURL]; exists {
		return peer.IdentityKey
	}
	return ""
}

// GetPeerSupportsMutualAuth returns whether the peer supports mutual auth.
func (a *AuthFetch) GetPeerSupportsMutualAuth(baseURL string) *bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if peer, exists := a.peers[baseURL]; exists {
		return peer.SupportsMutualAuth
	}
	return nil
}

// AddPendingCertificateRequest adds a pending certificate request for the peer.
func (a *AuthFetch) AddPendingCertificateRequest(baseURL string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if peer, exists := a.peers[baseURL]; exists {
		peer.PendingCertificateRequests = append(peer.PendingCertificateRequests, true)
	}
}

// RemovePendingCertificateRequest removes a pending certificate request for the peer.
func (a *AuthFetch) RemovePendingCertificateRequest(baseURL string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if peer, exists := a.peers[baseURL]; exists && len(peer.PendingCertificateRequests) > 0 {
		peer.PendingCertificateRequests = peer.PendingCertificateRequests[1:]
	}
}

// HasPendingCertificateRequests returns whether the peer has pending certificate requests.
func (a *AuthFetch) HasPendingCertificateRequests(baseURL string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if peer, exists := a.peers[baseURL]; exists {
		return len(peer.PendingCertificateRequests) > 0
	}
	return false
}

// InvokeCallback invokes and deletes the callback for the given nonce if it exists.
func (a *AuthFetch) InvokeCallback(nonce string, response interface{}) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if callback, ok := a.callbacks[nonce]; ok {
		callback.resolve(response)
		delete(a.callbacks, nonce)
		return true
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
	if paymentVersion != PaymentVersion {
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

	// Build a P2PKH locking script from the derived public key
	// Determine network for address construction
	mainnet := true
	if netRes, netErr := a.wallet.GetNetwork(ctx, nil, "auth-payment"); netErr == nil {
		if netRes.Network == wallet.NetworkTestnet {
			mainnet = false
		}
	}
	addr, err := script.NewAddressFromPublicKey(derivedKey.PublicKey, mainnet)
	if err != nil {
		return nil, fmt.Errorf("failed to create address from derived key: %w", err)
	}
	lockScript, err := p2pkh.Lock(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to create P2PKH locking script: %w", err)
	}

	randomizeOutputs := false
	actionResult, err := a.wallet.CreateAction(ctx, wallet.CreateActionArgs{
		Description: fmt.Sprintf("Payment for request to %s", urlStr),
		Outputs: []wallet.CreateActionOutput{
			{
				Satoshis:      satoshisRequired,
				LockingScript: lockScript.Bytes(),
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
