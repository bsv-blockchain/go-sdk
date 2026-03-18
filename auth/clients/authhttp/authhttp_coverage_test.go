package clients

// authhttp_coverage_test.go pushes coverage above 80% by exercising:
//   - The Fetch goroutine's full BRC-31 auth handshake (ListenForGeneralMessages
//     callback, ListenForCertificatesReceived/Requested registration, senderPublicKey branch)
//   - ErrHTTPServerFailedToAuthenticate fallback to handleFetchAndValidate
//   - identityKey != "" branch (line 517) and toPublicKeyError branch (line 519)
//   - hasPending() ticker loop (lines 498-505)
//   - 402 response dispatching to handlePaymentAndRetry (line 569)
//   - Second request re-using a stored peer (identityKey populated)
//   - Session-not-found retry branch (lines 526-537)
//   - SendCertificateRequest existing-peer reuse (line 592)

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/authpayload"
	"github.com/bsv-blockchain/go-sdk/auth/brc104"
	"github.com/bsv-blockchain/go-sdk/auth/transports"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const wellKnownAuthPath = "/.well-known/auth"

// ---------------------------------------------------------------------------
// channelTransport: an auth.Transport that routes messages via Go channels.
// Used to wire a server-side auth.Peer to an httptest.Server handler.
// ---------------------------------------------------------------------------

type channelTransport struct {
	handler func(context.Context, *auth.AuthMessage) error
	outCh   chan *auth.AuthMessage
}

func newChannelTransport() *channelTransport {
	return &channelTransport{
		outCh: make(chan *auth.AuthMessage, 8),
	}
}

func (ct *channelTransport) Send(_ context.Context, message *auth.AuthMessage) error {
	ct.outCh <- message
	return nil
}

func (ct *channelTransport) OnData(callback func(context.Context, *auth.AuthMessage) error) error {
	ct.handler = callback
	return nil
}

func (ct *channelTransport) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	if ct.handler == nil {
		return nil, fmt.Errorf("no handler registered")
	}
	return ct.handler, nil
}

// deliver feeds a message into the server peer's registered OnData handler.
func (ct *channelTransport) deliver(ctx context.Context, msg *auth.AuthMessage) error {
	if ct.handler == nil {
		return fmt.Errorf("no handler registered in channelTransport")
	}
	return ct.handler(ctx, msg)
}

// next reads the next outgoing message from the server peer (with timeout).
func (ct *channelTransport) next(timeout time.Duration) (*auth.AuthMessage, error) {
	select {
	case msg := <-ct.outCh:
		return msg, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout waiting for server transport outgoing message")
	}
}

// ---------------------------------------------------------------------------
// buildInProcessBRC31Server creates a full BRC-31 compliant httptest.Server.
//
//   - POST /.well-known/auth  → initialRequest handling
//   - All other paths          → general-message handling with BRC-104 response headers
//
// The response YourNonce is set to the client's session nonce (looked up via
// the shared serverSM) so that the client peer's handleGeneralMessage can
// verify it with its own wallet.
//
// responseStatusCode controls the HTTP status returned for general requests.
// Pass 0 for 200.
// ---------------------------------------------------------------------------

func buildInProcessBRC31Server(t *testing.T, responseStatusCode int) (*httptest.Server, *wallet.TestWallet) {
	t.Helper()

	if responseStatusCode == 0 {
		responseStatusCode = http.StatusOK
	}

	serverKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	serverWallet := wallet.NewTestWallet(t, serverKey)

	// Shared session manager so the HTTP handler can look up client nonces.
	serverSM := auth.NewSessionManager()

	ct := newChannelTransport()
	auth.NewPeer(&auth.PeerOptions{
		Wallet:         serverWallet,
		Transport:      ct,
		SessionManager: serverSM,
	})

	mux := http.NewServeMux()
	mux.HandleFunc(wellKnownAuthPath, buildAuthInitHandler(ct))
	mux.HandleFunc("/", buildGeneralMessageHandler(ct, serverSM, serverWallet, responseStatusCode))

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, serverWallet
}

// buildAuthInitHandler returns an HTTP handler for POST /.well-known/auth
// (initialRequest / certificateRequest).
func buildAuthInitHandler(ct *channelTransport) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, "read body", http.StatusInternalServerError)
			return
		}
		var inMsg auth.AuthMessage
		if unmarshalErr := json.Unmarshal(body, &inMsg); unmarshalErr != nil {
			http.Error(w, "bad JSON: "+unmarshalErr.Error(), http.StatusBadRequest)
			return
		}
		if deliverErr := ct.deliver(r.Context(), &inMsg); deliverErr != nil {
			http.Error(w, "peer error: "+deliverErr.Error(), http.StatusInternalServerError)
			return
		}
		outMsg, nextErr := ct.next(5 * time.Second)
		if nextErr != nil {
			http.Error(w, "no server response: "+nextErr.Error(), http.StatusGatewayTimeout)
			return
		}
		respBytes, marshalErr := json.Marshal(outMsg)
		if marshalErr != nil {
			http.Error(w, "marshal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBytes)
	}
}

// buildGeneralMessageHandler returns an HTTP handler for all non-auth paths.
// It processes BRC-104 signed general messages and writes signed response headers.
func buildGeneralMessageHandler(
	ct *channelTransport,
	serverSM *auth.DefaultSessionManager,
	serverWallet *wallet.TestWallet,
	responseStatusCode int,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		versionHeader := r.Header.Get(brc104.HeaderVersion)
		if versionHeader == "" {
			w.WriteHeader(responseStatusCode)
			return
		}

		identityKey, requestIDBase64, requestIDBytes, sigBytes, ok := parseIncomingHeaders(w, r)
		if !ok {
			return
		}

		payload, payloadErr := authpayload.FromHTTPRequest(requestIDBytes, r)
		if payloadErr != nil {
			http.Error(w, "payload error: "+payloadErr.Error(), http.StatusInternalServerError)
			return
		}

		serverSessionNonce := r.Header.Get(brc104.HeaderYourNonce)
		clientRequestNonce := r.Header.Get(brc104.HeaderNonce)

		inMsg := &auth.AuthMessage{
			Version:     versionHeader,
			MessageType: auth.MessageTypeGeneral,
			IdentityKey: identityKey,
			Nonce:       clientRequestNonce,
			YourNonce:   serverSessionNonce,
			Signature:   sigBytes,
			Payload:     payload,
		}

		if deliverErr := ct.deliver(r.Context(), inMsg); deliverErr != nil {
			http.Error(w, "peer general error: "+deliverErr.Error(), http.StatusInternalServerError)
			return
		}

		clientSessionNonce, ok := lookupClientNonce(w, serverSM, serverSessionNonce)
		if !ok {
			return
		}

		writeSignedResponse(w, r, signedResponseArgs{
			serverWallet:       serverWallet,
			identityKey:        identityKey,
			requestIDBase64:    requestIDBase64,
			requestIDBytes:     requestIDBytes,
			serverSessionNonce: serverSessionNonce,
			clientSessionNonce: clientSessionNonce,
			responseStatusCode: responseStatusCode,
		})
	}
}

// parseIncomingHeaders validates and decodes the BRC-104 request headers.
// Returns (identityKey, requestIDBase64, requestIDBytes, sigBytes, ok).
func parseIncomingHeaders(w http.ResponseWriter, r *http.Request) (*ec.PublicKey, string, []byte, []byte, bool) {
	identityKeyHex := r.Header.Get(brc104.HeaderIdentityKey)
	identityKey, pubKeyErr := ec.PublicKeyFromString(identityKeyHex)
	if pubKeyErr != nil {
		http.Error(w, "bad identity key", http.StatusBadRequest)
		return nil, "", nil, nil, false
	}

	sigHex := r.Header.Get(brc104.HeaderSignature)
	sigBytes, sigDecodeErr := hex.DecodeString(sigHex)
	if sigDecodeErr != nil {
		http.Error(w, "bad sig", http.StatusBadRequest)
		return nil, "", nil, nil, false
	}

	requestIDBase64 := r.Header.Get(brc104.HeaderRequestID)
	requestIDBytes, idDecodeErr := base64.StdEncoding.DecodeString(requestIDBase64)
	if idDecodeErr != nil {
		http.Error(w, "bad request id: "+idDecodeErr.Error(), http.StatusBadRequest)
		return nil, "", nil, nil, false
	}

	return identityKey, requestIDBase64, requestIDBytes, sigBytes, true
}

// lookupClientNonce retrieves the client's session nonce (PeerNonce) from the session
// manager using the server's session nonce. Returns (clientSessionNonce, ok).
func lookupClientNonce(w http.ResponseWriter, serverSM *auth.DefaultSessionManager, serverSessionNonce string) (string, bool) {
	serverSession, sessionErr := serverSM.GetSession(serverSessionNonce)
	if sessionErr != nil || serverSession == nil {
		http.Error(w, "session not found: "+serverSessionNonce, http.StatusInternalServerError)
		return "", false
	}
	return serverSession.PeerNonce, true
}

// signedResponseArgs bundles parameters for writeSignedResponse.
type signedResponseArgs struct {
	serverWallet       *wallet.TestWallet
	identityKey        *ec.PublicKey
	requestIDBase64    string
	requestIDBytes     []byte
	serverSessionNonce string
	clientSessionNonce string
	responseStatusCode int
}

// writeSignedResponse signs the response payload and writes BRC-104 response headers.
func writeSignedResponse(w http.ResponseWriter, r *http.Request, args signedResponseArgs) {
	serverWallet := args.serverWallet
	identityKey := args.identityKey
	requestIDBase64 := args.requestIDBase64
	requestIDBytes := args.requestIDBytes
	serverSessionNonce := args.serverSessionNonce
	clientSessionNonce := args.clientSessionNonce
	responseStatusCode := args.responseStatusCode
	_ = serverSessionNonce // kept for clarity; clientSessionNonce is derived from it

	ctx := r.Context()

	responsePayload, respPayloadErr := authpayload.FromResponse(requestIDBytes, authpayload.SimplifiedHttpResponse{
		StatusCode: responseStatusCode,
		Header:     make(http.Header),
		Body:       nil,
	})
	if respPayloadErr != nil {
		http.Error(w, "response payload error: "+respPayloadErr.Error(), http.StatusInternalServerError)
		return
	}

	idKeyResult, idKeyErr := serverWallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
		IdentityKey:    true,
		EncryptionArgs: wallet.EncryptionArgs{},
	}, "auth-peer")
	if idKeyErr != nil {
		http.Error(w, "get pubkey error", http.StatusInternalServerError)
		return
	}

	serverRespNonce, nonceErr := utils.CreateNonce(ctx, serverWallet, wallet.Counterparty{
		Type: wallet.CounterpartyTypeSelf,
	})
	if nonceErr != nil {
		http.Error(w, "create nonce error: "+nonceErr.Error(), http.StatusInternalServerError)
		return
	}

	sigResult, signErr := serverWallet.CreateSignature(ctx, wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
				Protocol:      "auth message signature",
			},
			KeyID: fmt.Sprintf("%s %s", serverRespNonce, clientSessionNonce),
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: identityKey,
			},
		},
		Data: responsePayload,
	}, "")
	if signErr != nil {
		http.Error(w, "sign error: "+signErr.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set(brc104.HeaderVersion, "0.1")
	w.Header().Set(brc104.HeaderIdentityKey, idKeyResult.PublicKey.ToDERHex())
	w.Header().Set(brc104.HeaderMessageType, string(auth.MessageTypeGeneral))
	w.Header().Set(brc104.HeaderNonce, serverRespNonce)
	w.Header().Set(brc104.HeaderYourNonce, clientSessionNonce)
	w.Header().Set(brc104.HeaderRequestID, requestIDBase64)
	w.Header().Set(brc104.HeaderSignature, hex.EncodeToString(sigResult.Signature.Serialize()))
	w.WriteHeader(responseStatusCode)
}

// buildNoAuthServer starts an httptest.Server that returns 501 on /.well-known/auth
// and the given statusCode on all other paths.  It is the caller's responsibility
// to close the server (use t.Cleanup or defer ts.Close()).
func buildNoAuthServer(t *testing.T, statusCode int) *httptest.Server {
	t.Helper()
	if statusCode == 0 {
		statusCode = http.StatusOK
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == wellKnownAuthPath {
			http.Error(w, `{"error":"not implemented"}`, http.StatusNotImplemented)
			return
		}
		w.WriteHeader(statusCode)
	}))
}

// buildPreloadedPeer creates a transport pointing at serverURL, wraps it in an
// AuthPeer backed by clientWallet, stores it in af.peers, and returns the peer.
// Optional fields (IdentityKey, SupportsMutualAuth, PendingCertificateRequests)
// can be set on the returned *AuthPeer after the call.
func buildPreloadedPeer(t *testing.T, af *AuthFetch, clientWallet wallet.Interface, serverURL string) *AuthPeer {
	t.Helper()
	transport, err := transports.NewSimplifiedHTTPTransport(&transports.SimplifiedHTTPTransportOptions{
		BaseURL: serverURL,
		Client:  &http.Client{},
	})
	require.NoError(t, err)
	peer := &AuthPeer{
		Peer: auth.NewPeer(&auth.PeerOptions{
			Wallet:    clientWallet,
			Transport: transport,
		}),
		PendingCertificateRequests: []bool{},
	}
	af.peers.Store(serverURL, peer)
	return peer
}

// ---------------------------------------------------------------------------
// TestFetchErrHTTPServerFailedToAuthenticateFallsBackToHandleFetchAndValidate
//
// The server returns 4xx on /.well-known/auth → transport joins
// ErrHTTPServerFailedToAuthenticate → Fetch falls back to handleFetchAndValidate
// (lines 472-479).  The regular endpoint returns 200.
// ---------------------------------------------------------------------------

func TestFetchErrHTTPServerFailedToAuthenticateFallsBackToHandleFetchAndValidate(t *testing.T) {
	ts := buildNoAuthServer(t, http.StatusOK)
	defer ts.Close()

	clientWallet := wallet.NewTestWalletForRandomKey(t)
	af := New(clientWallet, WithoutLogging())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := af.Fetch(ctx, ts.URL+"/test", &SimplifiedFetchRequestOptions{Method: "GET"})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// TestFetchErrHTTPServerFailedToAuthenticateWithKnownIdentityKey
//
// Same fallback, but the peer already has a valid IdentityKey stored.
// Exercises the identityKey != "" branch (line 517).
// ---------------------------------------------------------------------------

func TestFetchErrHTTPServerFailedToAuthenticateWithKnownIdentityKey(t *testing.T) {
	ts := buildNoAuthServer(t, http.StatusOK)
	defer ts.Close()

	clientWallet := wallet.NewTestWalletForRandomKey(t)
	af := New(clientWallet, WithoutLogging())

	// Pre-load a peer with a valid identity key.
	serverKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	validIdentityKey := serverKey.PubKey().ToDERHex()

	existingPeer := buildPreloadedPeer(t, af, clientWallet, ts.URL)
	existingPeer.IdentityKey = validIdentityKey

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := af.Fetch(ctx, ts.URL+"/test", &SimplifiedFetchRequestOptions{Method: "GET"})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// TestFetchErrHTTPServerFailedToAuthenticateWithInvalidIdentityKey
//
// Stored peer has an invalid identity key → toPublicKeyError != nil →
// idKeyObject reset to nil (line 519).
// ---------------------------------------------------------------------------

func TestFetchErrHTTPServerFailedToAuthenticateWithInvalidIdentityKey(t *testing.T) {
	ts := buildNoAuthServer(t, http.StatusOK)
	defer ts.Close()

	clientWallet := wallet.NewTestWalletForRandomKey(t)
	af := New(clientWallet, WithoutLogging())

	existingPeer := buildPreloadedPeer(t, af, clientWallet, ts.URL)
	existingPeer.IdentityKey = "not-a-valid-hex-public-key"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := af.Fetch(ctx, ts.URL+"/test", &SimplifiedFetchRequestOptions{Method: "GET"})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// TestFetchHasPendingCertificateRequestsTicker
//
// Exercises the hasPending() ticker loop (lines 498-505).
// The peer starts with PendingCertificateRequests populated; a goroutine
// clears it after 150 ms.  The Fetch goroutine waits in the ticker loop until
// it clears, then falls through to ToPeer which fails with
// ErrHTTPServerFailedToAuthenticate → handleFetchAndValidate → 200.
// ---------------------------------------------------------------------------

func TestFetchHasPendingCertificateRequestsTicker(t *testing.T) {
	ts := buildNoAuthServer(t, http.StatusOK)
	defer ts.Close()

	clientWallet := wallet.NewTestWalletForRandomKey(t)
	af := New(clientWallet, WithoutLogging())

	pendingPeer := buildPreloadedPeer(t, af, clientWallet, ts.URL)
	pendingPeer.PendingCertificateRequests = []bool{true}
	af.peers.Store(ts.URL, pendingPeer)

	// Clear the pending entry after 150 ms so the ticker loop exits.
	// We store a fresh AuthPeer (same Peer, empty PendingCertificateRequests)
	// rather than mutating the slice in place to avoid a data race.
	go func() {
		time.Sleep(150 * time.Millisecond)
		if p, ok := af.peers.Load(ts.URL); ok {
			oldPeer := p.(*AuthPeer)
			cleared := &AuthPeer{
				Peer:                       oldPeer.Peer,
				IdentityKey:                oldPeer.IdentityKey,
				SupportsMutualAuth:         oldPeer.SupportsMutualAuth,
				PendingCertificateRequests: []bool{},
			}
			af.peers.Store(ts.URL, cleared)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := af.Fetch(ctx, ts.URL+"/test", &SimplifiedFetchRequestOptions{Method: "GET"})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// TestFetchExistingPeerNonMutualAuthReused
//
// Pre-stores a peer with SupportsMutualAuth=false.  Fetch must reuse it and
// route through handleFetchAndValidate (lines 321-329).
// ---------------------------------------------------------------------------

func TestFetchExistingPeerNonMutualAuthReused(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	clientWallet := wallet.NewTestWalletForRandomKey(t)
	af := New(clientWallet, WithoutLogging())

	notSupported := false
	existingPeer := buildPreloadedPeer(t, af, clientWallet, ts.URL)
	existingPeer.SupportsMutualAuth = &notSupported

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := af.Fetch(ctx, ts.URL+"/test", &SimplifiedFetchRequestOptions{Method: "GET"})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// TestSendCertificateRequestExistingPeerLoaded
//
// Stores a peer for the target URL before calling SendCertificateRequest.
// Exercises the peers.Load reuse path (line 592-593).
// The call will time out (no real server), which is expected.
// ---------------------------------------------------------------------------

func TestSendCertificateRequestExistingPeerLoaded(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	clientWallet := wallet.NewTestWalletForRandomKey(t)
	af := New(clientWallet, WithoutLogging())

	buildPreloadedPeer(t, af, clientWallet, ts.URL)

	certSet := utils.RequestedCertificateSet{
		Certifiers:       []*ec.PublicKey{},
		CertificateTypes: make(utils.RequestedCertificateTypeIDAndFieldList),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	_, err := af.SendCertificateRequest(ctx, ts.URL+"/certs", &certSet)
	require.Error(t, err) // expected: context deadline or transport error
}

// ---------------------------------------------------------------------------
// TestFetchFullBRC31Auth200Response
//
// Full BRC-31 handshake exercising:
//   - ListenForCertificatesReceived callback registration (isNew=true, line 344)
//   - ListenForCertificatesRequested callback registration (line 352)
//   - ListenForGeneralMessages callback invocation (lines 390-488)
//   - senderPublicKey != nil branch (lines 393-399)
// ---------------------------------------------------------------------------

func TestFetchFullBRC31Auth200Response(t *testing.T) {
	ts, _ := buildInProcessBRC31Server(t, http.StatusOK)

	clientWallet := wallet.NewTestWalletForRandomKey(t)
	af := New(clientWallet, WithoutLogging())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := af.Fetch(ctx, ts.URL+"/test", &SimplifiedFetchRequestOptions{Method: "GET"})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// TestFetchFullBRC31Auth402ResponseTriggersHandlePaymentAndRetry
//
// Server responds with 402 to general messages.  The goroutine resolves with
// status 402 → line 569 dispatches to handlePaymentAndRetry.
// handlePaymentAndRetry fails because the decoded response lacks the
// x-bsv-payment-version header.
// ---------------------------------------------------------------------------

func TestFetchFullBRC31Auth402ResponseTriggersHandlePaymentAndRetry(t *testing.T) {
	ts, _ := buildInProcessBRC31Server(t, http.StatusPaymentRequired)

	clientWallet := wallet.NewTestWalletForRandomKey(t)
	af := New(clientWallet, WithoutLogging())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := af.Fetch(ctx, ts.URL+"/pay", &SimplifiedFetchRequestOptions{Method: "GET"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported x-bsv-payment-version")
}

// ---------------------------------------------------------------------------
// TestFetchFullBRC31AuthSecondRequestReusesPeer
//
// After a successful first request the peer is cached.  A second request
// reuses it (identityKey populated → line 517 branch).
// ---------------------------------------------------------------------------

func TestFetchFullBRC31AuthSecondRequestReusesPeer(t *testing.T) {
	ts, _ := buildInProcessBRC31Server(t, http.StatusOK)

	clientWallet := wallet.NewTestWalletForRandomKey(t)
	af := New(clientWallet, WithoutLogging())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp1, err := af.Fetch(ctx, ts.URL+"/first", &SimplifiedFetchRequestOptions{Method: "GET"})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	resp2, err := af.Fetch(ctx, ts.URL+"/second", &SimplifiedFetchRequestOptions{Method: "GET"})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
}

// ---------------------------------------------------------------------------
// TestFetchFullBRC31AuthSessionNotFoundRetry
//
// After a successful first handshake we wipe the client's session manager
// so the next ToPeer call returns "Session not found for nonce" →
// retry path lines 526-537.
// ---------------------------------------------------------------------------

func TestFetchFullBRC31AuthSessionNotFoundRetry(t *testing.T) {
	ts, _ := buildInProcessBRC31Server(t, http.StatusOK)

	clientWallet := wallet.NewTestWalletForRandomKey(t)
	sm := auth.NewSessionManager()
	af := New(clientWallet, WithSessionManager(sm), WithoutLogging())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// First request establishes a session.
	resp1, err := af.Fetch(ctx, ts.URL+"/init", &SimplifiedFetchRequestOptions{Method: "GET"})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	// Wipe the session manager and peer so ToPeer triggers "Session not found".
	af.sessionManager = auth.NewSessionManager()
	af.peers.Delete(ts.URL)

	resp2, err := af.Fetch(ctx, ts.URL+"/retry", &SimplifiedFetchRequestOptions{Method: "GET"})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
}

// ---------------------------------------------------------------------------
// TestFetchFullBRC31AuthCertificatesReceivedCallback
//
// Full handshake verifying that ConsumeReceivedCertificates works after a
// successful auth exchange (no certs expected, but callback was registered).
// ---------------------------------------------------------------------------

func TestFetchFullBRC31AuthCertificatesReceivedCallback(t *testing.T) {
	ts, _ := buildInProcessBRC31Server(t, http.StatusOK)

	clientWallet := wallet.NewTestWalletForRandomKey(t)
	af := New(clientWallet, WithoutLogging())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := af.Fetch(ctx, ts.URL+"/data", &SimplifiedFetchRequestOptions{
		Method: "POST",
		Body:   []byte(`{"key":"value"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	certs := af.ConsumeReceivedCertificates()
	assert.Empty(t, certs)
}

// ---------------------------------------------------------------------------
// TestSendCertificateRequestExistingPeerWithIdentityKey
//
// Exercises the IdentityKey != "" branch (lines 643/645) in
// SendCertificateRequest, where a stored peer has a known valid IdentityKey.
// ---------------------------------------------------------------------------

func TestSendCertificateRequestExistingPeerWithIdentityKey(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	clientWallet := wallet.NewTestWalletForRandomKey(t)
	af := New(clientWallet, WithoutLogging())

	serverKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	validIdentityKey := serverKey.PubKey().ToDERHex()

	existingPeer := buildPreloadedPeer(t, af, clientWallet, ts.URL)
	existingPeer.IdentityKey = validIdentityKey // valid key → identityKey != nil branch

	certSet := utils.RequestedCertificateSet{
		Certifiers:       []*ec.PublicKey{},
		CertificateTypes: make(utils.RequestedCertificateTypeIDAndFieldList),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	_, err = af.SendCertificateRequest(ctx, ts.URL+"/certs", &certSet)
	require.Error(t, err) // context timeout or transport error is expected
}

// ---------------------------------------------------------------------------
// TestHandlePaymentAndRetryRetryCounterNilSetsDefault
//
// Exercises the config.RetryCounter == nil branch (line 775) in
// handlePaymentAndRetry, which sets a default retry count of 3.
// We pass a nil RetryCounter; because the retry count is 3 the function will
// call Fetch recursively.  We make the recursive call immediately exhaust
// retries by forcing the retry to a URL that returns max-retries error.
// ---------------------------------------------------------------------------

func TestHandlePaymentAndRetryRetryCounterNilSetsDefault(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)

	serverKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	serverPubKeyHex := serverKey.PubKey().ToDERHex()

	af := New(tw, WithoutLogging())

	resp402 := &http.Response{
		StatusCode: 402,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("")),
	}
	resp402.Header.Set("x-bsv-payment-version", PaymentVersion)
	resp402.Header.Set("x-bsv-payment-satoshis-required", "100")
	resp402.Header.Set("x-bsv-auth-identity-key", serverPubKeyHex)
	resp402.Header.Set("x-bsv-payment-derivation-prefix", "pfx")

	// RetryCounter is nil → handlePaymentAndRetry sets it to 3.
	// The retry Fetch call (to "https://example.com") will fail because there is
	// no server.  After the transport error the function returns an error.
	config := &SimplifiedFetchRequestOptions{
		Method:       "GET",
		Headers:      nil,
		RetryCounter: nil, // intentionally nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = af.handlePaymentAndRetry(ctx, "https://127.0.0.1:0/pay", config, resp402)
	// Expected to fail (no server at 127.0.0.1:0), but the RetryCounter was set.
	require.Error(t, err)
	// After the call RetryCounter must NOT be nil (it was initialised to 3 then decremented).
	require.NotNil(t, config.RetryCounter)
}

// ---------------------------------------------------------------------------
// TestFetchFullBRC31AuthMultiplePaths
//
// Additional full-auth scenario that exercises multiple Fetch goroutine paths
// simultaneously by issuing concurrent requests after the first handshake.
// This helps cover the isNew=false (existing peer, mutual auth) branch.
// ---------------------------------------------------------------------------

func TestFetchFullBRC31AuthMultiplePaths(t *testing.T) {
	ts, _ := buildInProcessBRC31Server(t, http.StatusOK)

	clientWallet := wallet.NewTestWalletForRandomKey(t)
	af := New(clientWallet, WithoutLogging())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// First request → new peer created, handshake performed.
	resp1, err := af.Fetch(ctx, ts.URL+"/a", &SimplifiedFetchRequestOptions{Method: "GET"})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	// Second and third requests → peer reused (SupportsMutualAuth=true, identityKey set).
	resp2, err := af.Fetch(ctx, ts.URL+"/b", &SimplifiedFetchRequestOptions{Method: "POST", Body: []byte("body")})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	resp3, err := af.Fetch(ctx, ts.URL+"/c", &SimplifiedFetchRequestOptions{Method: "GET"})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp3.StatusCode)
}
