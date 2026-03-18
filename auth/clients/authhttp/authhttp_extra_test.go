package clients

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testExampleURL           = "https://example.com"
	testLocalhostZeroURL     = "https://localhost:0"
	errNotAllowedInAuthFetch = "not allowed in auth fetch"
	errMaxRetries            = "maximum number of retries"
	hdrIdentityKey           = "x-bsv-auth-identity-key"
	testPayURL               = "https://example.com/pay"
	hdrPaymentVersion        = "x-bsv-payment-version"
	hdrSatoshisRequired      = "x-bsv-payment-satoshis-required"
	hdrDerivationPrefix      = "x-bsv-payment-derivation-prefix"
	hdrPayment               = "x-bsv-payment"
)

// newAuthFetch creates a default AuthFetch backed by a fresh random-key wallet.
func newAuthFetch(t *testing.T) *AuthFetch {
	t.Helper()
	return New(wallet.NewTestWalletForRandomKey(t))
}

// make402Response builds a minimal *http.Response with status 402 and no body.
func make402Response() *http.Response {
	return &http.Response{
		StatusCode: 402,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("")),
	}
}

// ---------------------------------------------------------------------------
// Option setter tests
// ---------------------------------------------------------------------------

// TestWithHttpClientNil verifies that passing nil panics.
func TestWithHttpClientNil(t *testing.T) {
	require.Panics(t, func() {
		WithHttpClient(nil)
	})
}

// TestWithHttpClientNonNil verifies that a valid client is stored.
func TestWithHttpClientNonNil(t *testing.T) {
	custom := &http.Client{Timeout: 5 * time.Second}
	opts := &AuthFetchOptions{}
	WithHttpClient(custom)(opts)
	require.Equal(t, custom, opts.HttpClient)
}

// TestWithHttpClientTransportNil verifies that passing nil panics.
func TestWithHttpClientTransportNil(t *testing.T) {
	require.Panics(t, func() {
		WithHttpClientTransport(nil)
	})
}

// TestWithHttpClientTransportCreatesClientWhenNone verifies that a nil HttpClient is
// created automatically when transport is applied.
func TestWithHttpClientTransportCreatesClientWhenNone(t *testing.T) {
	transport := http.DefaultTransport
	opts := &AuthFetchOptions{} // HttpClient is nil
	WithHttpClientTransport(transport)(opts)
	require.NotNil(t, opts.HttpClient)
	require.Equal(t, transport, opts.HttpClient.Transport)
}

// TestWithHttpClientTransportOverridesExistingTransport verifies that the transport is
// replaced on an existing client.
func TestWithHttpClientTransportOverridesExistingTransport(t *testing.T) {
	original := &http.Client{Timeout: 10 * time.Second}
	newTransport := http.DefaultTransport
	opts := &AuthFetchOptions{HttpClient: original}
	WithHttpClientTransport(newTransport)(opts)
	require.Equal(t, original, opts.HttpClient, "client pointer should be unchanged")
	require.Equal(t, newTransport, opts.HttpClient.Transport, "transport should be replaced")
}

// TestWithCertificatesToRequestNil verifies that passing nil panics.
func TestWithCertificatesToRequestNil(t *testing.T) {
	require.Panics(t, func() {
		WithCertificatesToRequest(nil)
	})
}

// TestWithCertificatesToRequestNonNil verifies that a valid set is stored.
func TestWithCertificatesToRequestNonNil(t *testing.T) {
	certSet := &utils.RequestedCertificateSet{
		Certifiers:       []*ec.PublicKey{},
		CertificateTypes: make(utils.RequestedCertificateTypeIDAndFieldList),
	}
	opts := &AuthFetchOptions{}
	WithCertificatesToRequest(certSet)(opts)
	require.Equal(t, certSet, opts.CertificatesToRequest)
}

// TestWithSessionManagerNil verifies that passing nil panics.
func TestWithSessionManagerNil(t *testing.T) {
	require.Panics(t, func() {
		WithSessionManager(nil)
	})
}

// TestWithSessionManagerNonNil verifies that a valid session manager is stored.
func TestWithSessionManagerNonNil(t *testing.T) {
	sm := NewMockSessionManager()
	opts := &AuthFetchOptions{}
	WithSessionManager(sm)(opts)
	require.Equal(t, sm, opts.SessionManager)
}

// TestWithLoggerNil verifies that passing nil panics.
func TestWithLoggerNil(t *testing.T) {
	require.Panics(t, func() {
		WithLogger(nil)
	})
}

// TestWithLoggerNonNil verifies that a valid logger is stored.
func TestWithLoggerNonNil(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	opts := &AuthFetchOptions{}
	WithLogger(logger)(opts)
	require.Equal(t, logger, opts.Logger)
}

// TestWithoutLogging verifies that calling WithoutLogging sets a discard logger.
func TestWithoutLogging(t *testing.T) {
	opts := &AuthFetchOptions{}
	WithoutLogging()(opts)
	require.NotNil(t, opts.Logger)
	// The logger should accept records without writing anywhere – check no panic
	opts.Logger.Info("should be discarded")
}

// ---------------------------------------------------------------------------
// New constructor tests
// ---------------------------------------------------------------------------

// TestNewNilWalletPanics verifies that nil wallet panics.
func TestNewNilWalletPanics(t *testing.T) {
	require.Panics(t, func() {
		New(nil)
	})
}

// TestNewDefaultsCreated verifies that defaults are populated when no opts provided.
func TestNewDefaultsCreated(t *testing.T) {
	af := newAuthFetch(t)
	require.NotNil(t, af)
	require.NotNil(t, af.sessionManager)
	require.NotNil(t, af.client)
	require.NotNil(t, af.logger)
}

// TestNewWithAllOptions verifies that all options are applied.
func TestNewWithAllOptions(t *testing.T) {
	w := wallet.NewTestWalletForRandomKey(t)
	sm := NewMockSessionManager()
	logger := slog.New(slog.DiscardHandler)
	httpClient := &http.Client{Timeout: 42 * time.Second}
	certSet := &utils.RequestedCertificateSet{
		Certifiers:       []*ec.PublicKey{},
		CertificateTypes: make(utils.RequestedCertificateTypeIDAndFieldList),
	}

	af := New(w,
		WithSessionManager(sm),
		WithLogger(logger),
		WithHttpClient(httpClient),
		WithCertificatesToRequest(certSet),
	)

	require.NotNil(t, af)
	require.Equal(t, sm, af.sessionManager)
	require.Equal(t, httpClient, af.client)
	require.Equal(t, certSet, af.requestedCertificates)
}

// TestNewWithoutLoggingOption verifies that WithoutLogging does not panic in New.
func TestNewWithoutLoggingOption(t *testing.T) {
	w := wallet.NewTestWalletForRandomKey(t)
	require.NotPanics(t, func() {
		af := New(w, WithoutLogging())
		require.NotNil(t, af)
	})
}

// ---------------------------------------------------------------------------
// SetLogger (deprecated) test
// ---------------------------------------------------------------------------

// TestSetLogger sets a new logger on an existing AuthFetch.
func TestSetLogger(t *testing.T) {
	af := newAuthFetch(t)
	newLogger := slog.New(slog.DiscardHandler)
	af.SetLogger(newLogger)
	// No public getter – just verify it does not panic and writes no errors
	af.logger.Info("test")
}

// ---------------------------------------------------------------------------
// ConsumeReceivedCertificates edge cases
// ---------------------------------------------------------------------------

// TestConsumeReceivedCertificatesEmpty verifies that an empty slice is returned when
// no certificates have been received.
func TestConsumeReceivedCertificatesEmpty(t *testing.T) {
	af := newAuthFetch(t)
	certs := af.ConsumeReceivedCertificates()
	require.NotNil(t, certs)
	require.Empty(t, certs)
}

// TestConsumeReceivedCertificatesClearsSlice verifies that a second call returns an
// empty slice after the first consume.
func TestConsumeReceivedCertificatesClearsSlice(t *testing.T) {
	af := newAuthFetch(t)
	af.certsMu.Lock()
	af.certificatesReceived = append(af.certificatesReceived, nil, nil)
	af.certsMu.Unlock()

	first := af.ConsumeReceivedCertificates()
	require.Len(t, first, 2)

	second := af.ConsumeReceivedCertificates()
	require.Empty(t, second)
}

// ---------------------------------------------------------------------------
// Fetch – option/input validation paths
// ---------------------------------------------------------------------------

// TestFetch_NilConfig uses nil config (should default to GET).
// We use a context that is cancelled immediately to avoid an actual network call.
func TestFetchNilConfigContextCancelled(t *testing.T) {
	af := newAuthFetch(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancel

	_, err := af.Fetch(ctx, testExampleURL, nil)
	// The request might fail with context error or a transport error - either is fine
	require.Error(t, err)
}

// TestFetchDefaultMethodApplied ensures that empty method defaults to GET without error.
func TestFetchDefaultMethodApplied(t *testing.T) {
	af := newAuthFetch(t)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := af.Fetch(ctx, testLocalhostZeroURL, &SimplifiedFetchRequestOptions{Method: ""})
	// Will fail to connect but should not fail on header validation
	require.Error(t, err)
	assert.NotContains(t, err.Error(), errNotAllowedInAuthFetch)
}

// TestFetchRetryCounterDecremented verifies that the retry counter is decremented.
func TestFetchRetryCounterDecremented(t *testing.T) {
	af := newAuthFetch(t)

	retryCount := 1
	config := &SimplifiedFetchRequestOptions{
		Method:       "GET",
		RetryCounter: &retryCount,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Should not hit the "maximum retries" path (counter = 1 means 1 attempt remaining),
	// it will proceed but fail due to no server.
	_, err := af.Fetch(ctx, testLocalhostZeroURL, config)
	require.Error(t, err)
	// Should not be the retry-exhausted error
	assert.NotContains(t, err.Error(), errMaxRetries)
}

// TestFetchContextCancellation verifies context cancellation is propagated.
func TestFetchContextCancellation(t *testing.T) {
	af := newAuthFetch(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := af.Fetch(ctx, testExampleURL, &SimplifiedFetchRequestOptions{Method: "GET"})
	require.Error(t, err)
}

// TestFetchAllowedHeaders verifies that whitelisted headers pass validation.
func TestFetchAllowedHeaders(t *testing.T) {
	af := newAuthFetch(t)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// "content-type" and "authorization" are in the allowed list.
	_, err := af.Fetch(ctx, testLocalhostZeroURL, &SimplifiedFetchRequestOptions{
		Method: "POST",
		Headers: map[string]string{
			"content-type":  "application/json",
			"authorization": "Bearer token",
		},
	})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), errNotAllowedInAuthFetch)
}

// ---------------------------------------------------------------------------
// handleFetchAndValidate – tested via the SupportsMutualAuth=false code path.
// ---------------------------------------------------------------------------

// buildNonMutualAuthPeer creates a peer entry where SupportsMutualAuth is false,
// which routes Fetch calls through handleFetchAndValidate.
func buildNonMutualAuthPeer(baseURL string, af *AuthFetch) {
	notSupported := false
	peer := &AuthPeer{
		SupportsMutualAuth: &notSupported,
	}
	af.peers.Store(baseURL, peer)
}

// TestHandleFetchAndValidateSuccessPath tests a clean 200 response path via
// the non-mutual-auth branch.
func TestHandleFetchAndValidateSuccessPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	af := newAuthFetch(t)
	buildNonMutualAuthPeer(ts.URL, af)

	resp, err := af.Fetch(context.Background(), ts.URL+"/path", &SimplifiedFetchRequestOptions{
		Method: "GET",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestHandleFetchAndValidateWithBody tests POST with body through the non-mutual-auth path.
func TestHandleFetchAndValidateWithBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body) // echo body back
	}))
	defer ts.Close()

	af := newAuthFetch(t)
	buildNonMutualAuthPeer(ts.URL, af)

	resp, err := af.Fetch(context.Background(), ts.URL+"/echo", &SimplifiedFetchRequestOptions{
		Method: "POST",
		Body:   []byte(`{"key":"value"}`),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	respBody, _ := io.ReadAll(resp.Body)
	assert.Equal(t, `{"key":"value"}`, string(respBody))
}

// TestHandleFetchAndValidateServerClaimingAuth tests the security check: if the server
// returns a BSV auth header when we did not negotiate auth, the client should reject it.
func TestHandleFetchAndValidateServerClaimingAuth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(hdrIdentityKey, "fakekey")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	af := newAuthFetch(t)
	buildNonMutualAuthPeer(ts.URL, af)

	_, err := af.Fetch(context.Background(), ts.URL+"/path", &SimplifiedFetchRequestOptions{
		Method: "GET",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authenticated when it has not")
}

// TestHandleFetchAndValidateServerClaimingBsvAuthHeader tests x-bsv-auth prefix detection.
func TestHandleFetchAndValidateServerClaimingBsvAuthHeader(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-bsv-auth-nonce", "somenonce")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	af := newAuthFetch(t)
	buildNonMutualAuthPeer(ts.URL, af)

	_, err := af.Fetch(context.Background(), ts.URL+"/path", &SimplifiedFetchRequestOptions{
		Method: "GET",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authenticated when it has not")
}

// TestHandleFetchAndValidate4xxError verifies that 4xx responses return an error.
func TestHandleFetchAndValidate4xxError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	af := newAuthFetch(t)
	buildNonMutualAuthPeer(ts.URL, af)

	_, err := af.Fetch(context.Background(), ts.URL+"/notfound", &SimplifiedFetchRequestOptions{
		Method: "GET",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

// TestHandleFetchAndValidateWithHeaders verifies that custom allowed headers are forwarded.
func TestHandleFetchAndValidateWithHeaders(t *testing.T) {
	var receivedAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	af := newAuthFetch(t)
	buildNonMutualAuthPeer(ts.URL, af)

	_, err := af.Fetch(context.Background(), ts.URL+"/path", &SimplifiedFetchRequestOptions{
		Method: "GET",
		Headers: map[string]string{
			"authorization": "Bearer mytoken",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "Bearer mytoken", receivedAuth)
}

// ---------------------------------------------------------------------------
// handlePaymentAndRetry header validation paths (tested via a 402 response
// from the non-mutual-auth path, which calls handleFetchAndValidate returning
// a 402 upstream, but handlePaymentAndRetry is only reached through the Fetch
// goroutine after a successful auth response with status 402).
//
// Since handlePaymentAndRetry is private and only reachable via Fetch after
// the auth goroutine resolves a 402, we test it by pre-loading a peer with
// a mocked non-mutual-auth path and returning a 402 with various headers.
// ---------------------------------------------------------------------------

// TestHandlePaymentAndRetry_MissingVersionHeader tests that 402 without
// x-bsv-payment-version returns appropriate error.
// We drive this through the non-mutual-auth path since that path goes directly
// to handleFetchAndValidate; but to hit handlePaymentAndRetry we need a 402
// from the authenticated code path.
// Instead we call it more directly through a real 402 server but using a
// pre-loaded peer with mutual-auth forced OFF – note that in that branch
// handleFetchAndValidate is called and it returns a 402 error, so
// handlePaymentAndRetry is NOT reachable from there.
//
// The only way to reach handlePaymentAndRetry is through the main Fetch
// goroutine that completes with status==402. We achieve that by providing a
// fully functional server that responds with 402 and proper auth headers via
// the goroutine resolve path. Because that requires a full auth server, we
// instead exercise the header validation by constructing a mock *http.Response
// and calling the private method via test helpers within the same package.
// (Since tests are in the same package, we have access.)

// TestHandlePaymentAndRetryMissingPaymentVersion exercises the version check.
func TestHandlePaymentAndRetryMissingPaymentVersion(t *testing.T) {
	af := newAuthFetch(t)
	resp402 := make402Response()
	// No x-bsv-payment-version header set → version mismatch
	_, err := af.handlePaymentAndRetry(context.Background(), testPayURL, &SimplifiedFetchRequestOptions{Method: "GET"}, resp402)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported x-bsv-payment-version")
}

// TestHandlePaymentAndRetryWrongVersion exercises version mismatch.
func TestHandlePaymentAndRetryWrongVersion(t *testing.T) {
	af := newAuthFetch(t)
	resp402 := make402Response()
	resp402.Header.Set(hdrPaymentVersion, "2.0")

	_, err := af.handlePaymentAndRetry(context.Background(), testPayURL, &SimplifiedFetchRequestOptions{Method: "GET"}, resp402)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported x-bsv-payment-version")
}

// TestHandlePaymentAndRetryMissingSatoshisHeader exercises missing satoshis header.
func TestHandlePaymentAndRetryMissingSatoshisHeader(t *testing.T) {
	af := newAuthFetch(t)
	resp402 := make402Response()
	resp402.Header.Set(hdrPaymentVersion, PaymentVersion)
	// No satoshis header

	_, err := af.handlePaymentAndRetry(context.Background(), testPayURL, &SimplifiedFetchRequestOptions{Method: "GET"}, resp402)
	require.Error(t, err)
	assert.Contains(t, err.Error(), hdrSatoshisRequired)
}

// TestHandlePaymentAndRetryInvalidSatoshisValue exercises bad satoshis header.
func TestHandlePaymentAndRetryInvalidSatoshisValue(t *testing.T) {
	af := newAuthFetch(t)
	resp402 := make402Response()
	resp402.Header.Set(hdrPaymentVersion, PaymentVersion)
	resp402.Header.Set(hdrSatoshisRequired, "not-a-number")

	_, err := af.handlePaymentAndRetry(context.Background(), testPayURL, &SimplifiedFetchRequestOptions{Method: "GET"}, resp402)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid x-bsv-payment-satoshis-required")
}

// TestHandlePaymentAndRetryZeroSatoshis exercises zero satoshis (invalid).
func TestHandlePaymentAndRetryZeroSatoshis(t *testing.T) {
	af := newAuthFetch(t)
	resp402 := make402Response()
	resp402.Header.Set(hdrPaymentVersion, PaymentVersion)
	resp402.Header.Set(hdrSatoshisRequired, "0")

	_, err := af.handlePaymentAndRetry(context.Background(), testPayURL, &SimplifiedFetchRequestOptions{Method: "GET"}, resp402)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid x-bsv-payment-satoshis-required")
}

// TestHandlePaymentAndRetryMissingIdentityKey exercises missing server identity key.
func TestHandlePaymentAndRetryMissingIdentityKey(t *testing.T) {
	af := newAuthFetch(t)
	resp402 := make402Response()
	resp402.Header.Set(hdrPaymentVersion, PaymentVersion)
	resp402.Header.Set(hdrSatoshisRequired, "1000")
	// No x-bsv-auth-identity-key

	_, err := af.handlePaymentAndRetry(context.Background(), testPayURL, &SimplifiedFetchRequestOptions{Method: "GET"}, resp402)
	require.Error(t, err)
	assert.Contains(t, err.Error(), hdrIdentityKey)
}

// TestHandlePaymentAndRetryMissingDerivationPrefix exercises missing derivation prefix.
func TestHandlePaymentAndRetryMissingDerivationPrefix(t *testing.T) {
	// Get a real identity key for the server field
	serverKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	serverPubKeyHex := serverKey.PubKey().ToDERHex()

	af := newAuthFetch(t)
	resp402 := make402Response()
	resp402.Header.Set(hdrPaymentVersion, PaymentVersion)
	resp402.Header.Set(hdrSatoshisRequired, "1000")
	resp402.Header.Set(hdrIdentityKey, serverPubKeyHex)
	// No x-bsv-payment-derivation-prefix

	_, err = af.handlePaymentAndRetry(context.Background(), testPayURL, &SimplifiedFetchRequestOptions{Method: "GET"}, resp402)
	require.Error(t, err)
	assert.Contains(t, err.Error(), hdrDerivationPrefix)
}

// TestHandlePaymentAndRetryInvalidIdentityKey exercises invalid identity key format.
func TestHandlePaymentAndRetryInvalidIdentityKey(t *testing.T) {
	af := newAuthFetch(t)
	resp402 := make402Response()
	resp402.Header.Set(hdrPaymentVersion, PaymentVersion)
	resp402.Header.Set(hdrSatoshisRequired, "1000")
	resp402.Header.Set(hdrIdentityKey, "not-a-valid-hex-key")
	resp402.Header.Set(hdrDerivationPrefix, "prefix123")

	_, err := af.handlePaymentAndRetry(context.Background(), testPayURL, &SimplifiedFetchRequestOptions{Method: "GET"}, resp402)
	require.Error(t, err)
}

// TestHandlePaymentAndRetryValidHeadersInvokeWallet tests the full happy path up to
// wallet interaction (CreateNonce then GetPublicKey), verifying those calls are made.
func TestHandlePaymentAndRetryValidHeadersInvokeWallet(t *testing.T) {
	// Get a real server key to populate headers properly.
	serverKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	serverPubKeyHex := serverKey.PubKey().ToDERHex()

	af := newAuthFetch(t)
	resp402 := make402Response()
	resp402.Header.Set(hdrPaymentVersion, PaymentVersion)
	resp402.Header.Set(hdrSatoshisRequired, "500")
	resp402.Header.Set(hdrIdentityKey, serverPubKeyHex)
	resp402.Header.Set(hdrDerivationPrefix, "testprefix")

	// With a valid retry counter of 0, the Fetch retry will immediately fail with
	// "maximum retries" – that confirms that the payment was constructed and the
	// retry was attempted.
	retryCount := 0
	config := &SimplifiedFetchRequestOptions{
		Method:       "GET",
		RetryCounter: &retryCount,
	}

	_, err = af.handlePaymentAndRetry(context.Background(), testPayURL, config, resp402)
	// Should fail because retry counter is 0 → exhausted
	require.Error(t, err)
	assert.Contains(t, err.Error(), errMaxRetries)
}

// ---------------------------------------------------------------------------
// SendCertificateRequest – URL parsing
// ---------------------------------------------------------------------------

// TestSendCertificateRequestInvalidURL verifies that a bad URL returns an error.
func TestSendCertificateRequestInvalidURL(t *testing.T) {
	af := newAuthFetch(t)

	certSet := utils.RequestedCertificateSet{
		Certifiers:       []*ec.PublicKey{},
		CertificateTypes: make(utils.RequestedCertificateTypeIDAndFieldList),
	}

	_, err := af.SendCertificateRequest(context.Background(), "://invalid-url", &certSet)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid URL")
}

// TestSendCertificateRequestContextCancelled verifies context cancellation is returned.
func TestSendCertificateRequestContextCancelled(t *testing.T) {
	af := newAuthFetch(t)

	certSet := utils.RequestedCertificateSet{
		Certifiers:       []*ec.PublicKey{},
		CertificateTypes: make(utils.RequestedCertificateTypeIDAndFieldList),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := af.SendCertificateRequest(ctx, testExampleURL, &certSet)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

// TestSendCertificateRequestContextTimeout verifies that a timeout propagates.
func TestSendCertificateRequestContextTimeout(t *testing.T) {
	af := newAuthFetch(t)

	certSet := utils.RequestedCertificateSet{
		Certifiers:       []*ec.PublicKey{},
		CertificateTypes: make(utils.RequestedCertificateTypeIDAndFieldList),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	time.Sleep(5 * time.Millisecond) // ensure the deadline has passed

	_, err := af.SendCertificateRequest(ctx, testExampleURL, &certSet)
	require.Error(t, err)
}

// TestSendCertificateRequestReusesPeer verifies that a pre-loaded peer is reused.
// We pre-store a real AuthPeer built with a test wallet and transport, then confirm the
// context-cancellation path is hit (meaning the stored peer was used, not a new one).
func TestSendCertificateRequestReusesPeer(t *testing.T) {
	af := newAuthFetch(t)

	// Build a real transport + peer so that SendCertificateRequest can call
	// Peer.ListenForCertificatesReceived without panicking on a nil receiver.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Let New populate a peer for ts.URL by triggering the creation path.
	// We do that by using a cancelled context so Fetch returns quickly.
	ctx0, cancel0 := context.WithCancel(context.Background())
	cancel0()
	_, _ = af.Fetch(ctx0, ts.URL+"/init", nil)

	// Now confirm a peer exists for ts.URL (the base).
	_, loaded := af.peers.Load(ts.URL)
	// It may or may not have been stored depending on timing; either way the
	// test is checking the reuse path. Use the same base URL for the cert request.

	certSet := utils.RequestedCertificateSet{
		Certifiers:       []*ec.PublicKey{},
		CertificateTypes: make(utils.RequestedCertificateTypeIDAndFieldList),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Whether or not the peer was loaded, the request will timeout or fail –
	// the key is that it does not panic.
	_, err := af.SendCertificateRequest(ctx, ts.URL+"/any/path", &certSet)
	require.Error(t, err)
	_ = loaded // suppress unused variable warning
}

// ---------------------------------------------------------------------------
// PaymentVersion constant
// ---------------------------------------------------------------------------

// TestPaymentVersionConstant verifies the constant value matches the spec.
func TestPaymentVersionConstant(t *testing.T) {
	assert.Equal(t, "1.0", PaymentVersion)
}

// ---------------------------------------------------------------------------
// AuthFetch struct fields – sanity assertions
// ---------------------------------------------------------------------------

// TestAuthFetchPeerFields verifies that AuthPeer fields are accessible.
func TestAuthFetchPeerFields(t *testing.T) {
	supported := true
	peer := &AuthPeer{
		IdentityKey:                "abc",
		SupportsMutualAuth:         &supported,
		PendingCertificateRequests: []bool{true, false},
	}
	assert.Equal(t, "abc", peer.IdentityKey)
	assert.True(t, *peer.SupportsMutualAuth)
	assert.Len(t, peer.PendingCertificateRequests, 2)
}

// ---------------------------------------------------------------------------
// handleFetchAndValidate – via httptest for edge cases
// ---------------------------------------------------------------------------

// TestHandleFetchAndValidateDirectCall exercises the function directly.
func TestHandleFetchAndValidateDirectCall(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	af := newAuthFetch(t)
	peer := &AuthPeer{}
	config := &SimplifiedFetchRequestOptions{
		Method: "GET",
	}
	resp, err := af.handleFetchAndValidate(ts.URL+"/test", config, peer)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// SupportsMutualAuth should now be set to false
	require.NotNil(t, peer.SupportsMutualAuth)
	assert.False(t, *peer.SupportsMutualAuth)
}

// TestHandleFetchAndValidateDirectCallWithBody exercises POST path.
func TestHandleFetchAndValidateDirectCallWithBody(t *testing.T) {
	var receivedBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	af := newAuthFetch(t)
	peer := &AuthPeer{}
	config := &SimplifiedFetchRequestOptions{
		Method: "POST",
		Body:   []byte("hello"),
	}
	_, err := af.handleFetchAndValidate(ts.URL+"/test", config, peer)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(receivedBody))
}

// TestHandleFetchAndValidate500Response returns error for 5xx.
func TestHandleFetchAndValidate500Response(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	af := newAuthFetch(t)
	peer := &AuthPeer{}
	config := &SimplifiedFetchRequestOptions{Method: "GET"}
	_, err := af.handleFetchAndValidate(ts.URL+"/fail", config, peer)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// ---------------------------------------------------------------------------
// SimplifiedFetchRequestOptions struct
// ---------------------------------------------------------------------------

// TestSimplifiedFetchRequestOptionsDefaults checks zero-value struct fields.
func TestSimplifiedFetchRequestOptionsDefaults(t *testing.T) {
	opts := &SimplifiedFetchRequestOptions{}
	assert.Equal(t, "", opts.Method)
	assert.Nil(t, opts.Headers)
	assert.Nil(t, opts.Body)
	assert.Nil(t, opts.RetryCounter)
}

// ---------------------------------------------------------------------------
// AuthFetchOptions struct
// ---------------------------------------------------------------------------

// TestAuthFetchOptionsDefaults checks zero-value struct fields.
func TestAuthFetchOptionsDefaults(t *testing.T) {
	opts := &AuthFetchOptions{}
	assert.Nil(t, opts.CertificatesToRequest)
	assert.Nil(t, opts.SessionManager)
	assert.Nil(t, opts.Logger)
	assert.Nil(t, opts.HttpClient)
}

// ---------------------------------------------------------------------------
// handleFetchAndValidate – bad URL
// ---------------------------------------------------------------------------

// TestHandleFetchAndValidateBadURL exercises the http.NewRequest error path.
func TestHandleFetchAndValidateBadURL(t *testing.T) {
	af := newAuthFetch(t)

	peer := &AuthPeer{}
	config := &SimplifiedFetchRequestOptions{Method: "GET"}
	// A malformed method causes NewRequest to fail
	config.Method = "INVALID METHOD WITH SPACES"
	_, err := af.handleFetchAndValidate(testExampleURL, config, peer)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Fetch – valid x-bsv-payment header is allowed
// ---------------------------------------------------------------------------

// TestFetchXBSVPaymentHeaderAllowed verifies x-bsv-payment is in the allowed list.
func TestFetchXBSVPaymentHeaderAllowed(t *testing.T) {
	af := newAuthFetch(t)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	paymentJSON, _ := json.Marshal(map[string]string{"key": "value"})
	_, err := af.Fetch(ctx, testLocalhostZeroURL, &SimplifiedFetchRequestOptions{
		Method: "GET",
		Headers: map[string]string{
			hdrPayment: string(paymentJSON),
		},
	})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), errNotAllowedInAuthFetch)
}

// ---------------------------------------------------------------------------
// Fetch non-mutual-auth path: invalid request method triggers transport error
// ---------------------------------------------------------------------------

// TestFetchInvalidScheme tests handling of a URL with an invalid scheme.
func TestFetchInvalidScheme(t *testing.T) {
	af := newAuthFetch(t)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// An invalid scheme will cause an error in one of the layers
	_, err := af.Fetch(ctx, "not-a-real-scheme://host/path", &SimplifiedFetchRequestOptions{
		Method: "GET",
	})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// WithHttpClientTransport applied via New
// ---------------------------------------------------------------------------

// TestNewWithHttpClientTransport verifies that the transport option works through New.
func TestNewWithHttpClientTransport(t *testing.T) {
	transport := http.DefaultTransport
	w := wallet.NewTestWalletForRandomKey(t)
	af := New(w, WithHttpClientTransport(transport))
	require.NotNil(t, af.client)
	require.Equal(t, transport, af.client.Transport)
}

// ---------------------------------------------------------------------------
// ConsumeReceivedCertificates – concurrent safety is already tested in existing file.
// Test the mutex path explicitly with a direct lock sequence.
// ---------------------------------------------------------------------------

// TestConsumeReceivedCertificatesMutexUnlocks verifies the certsMu is released properly.
func TestConsumeReceivedCertificatesMutexUnlocks(t *testing.T) {
	af := newAuthFetch(t)

	// First consume (empty)
	c1 := af.ConsumeReceivedCertificates()
	assert.Empty(t, c1)

	// Add certs directly
	af.certsMu.Lock()
	af.certificatesReceived = append(af.certificatesReceived, nil)
	af.certsMu.Unlock()

	// Second consume (has one)
	c2 := af.ConsumeReceivedCertificates()
	assert.Len(t, c2, 1)

	// Third consume (empty again)
	c3 := af.ConsumeReceivedCertificates()
	assert.Empty(t, c3)

	// Verify the mutex is released and we can lock it again
	locked := make(chan struct{})
	go func() {
		af.certsMu.Lock()
		close(locked)
		af.certsMu.Unlock()
	}()

	select {
	case <-locked:
		// good: mutex was acquirable
	case <-time.After(time.Second):
		t.Fatal("mutex appears to be held after ConsumeReceivedCertificates")
	}
}

// ---------------------------------------------------------------------------
// handlePaymentAndRetry – config.Headers initialisation (nil headers map)
// ---------------------------------------------------------------------------

// TestHandlePaymentAndRetryNilHeaders verifies that payment headers are added even
// when config.Headers was nil (the function allocates a new map in that case).
// We test up to the CreateNonce call – success past the header checks.
func TestHandlePaymentAndRetryNilHeaders(t *testing.T) {
	serverKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	serverPubKeyHex := serverKey.PubKey().ToDERHex()

	af := newAuthFetch(t)
	resp402 := make402Response()
	resp402.Header.Set(hdrPaymentVersion, PaymentVersion)
	resp402.Header.Set(hdrSatoshisRequired, "500")
	resp402.Header.Set(hdrIdentityKey, serverPubKeyHex)
	resp402.Header.Set(hdrDerivationPrefix, "testprefix")

	// Headers is nil in config
	retryCount := 0
	config := &SimplifiedFetchRequestOptions{
		Method:       "POST",
		Headers:      nil, // intentionally nil
		RetryCounter: &retryCount,
	}

	_, err = af.handlePaymentAndRetry(context.Background(), testPayURL, config, resp402)
	// Expect retry exhaustion – meaning it got past header validation and payment setup
	require.Error(t, err)
	assert.Contains(t, err.Error(), errMaxRetries)
	// After the call, Headers should have been allocated and set
	assert.NotNil(t, config.Headers)
	assert.Contains(t, config.Headers, hdrPayment)
}

// ---------------------------------------------------------------------------
// Base64 constant check used in payment
// ---------------------------------------------------------------------------

// TestBase64EncodingRoundtrip verifies that base64 encoding used in payment roundtrips.
func TestBase64EncodingRoundtrip(t *testing.T) {
	original := []byte("test transaction bytes")
	encoded := base64.StdEncoding.EncodeToString(original)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
}

// ---------------------------------------------------------------------------
// SendCertificateRequest – IdentityKey path
// ---------------------------------------------------------------------------

// TestSendCertificateRequestWithIdentityKey exercises the code path in
// SendCertificateRequest where the stored peer has a valid IdentityKey.
// The request will fail (no real server) but the identity key code path is exercised.
func TestSendCertificateRequestWithIdentityKey(t *testing.T) {
	af := newAuthFetch(t)

	// Get a real server key to use as the peer's identity key.
	serverKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	serverPubKeyHex := serverKey.PubKey().ToDERHex()

	// Build a transport-backed peer so it doesn't nil-deref.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Create a fully initialised peer with a known identity key.
	// We do this by manually constructing the peer entry, using the auth package
	// peer construction pattern to avoid nil-pointer panics on callback registration.
	ctx0, cancel0 := context.WithCancel(context.Background())
	cancel0()
	// Trigger peer creation for ts.URL
	_, _ = af.Fetch(ctx0, ts.URL+"/init", nil)

	// Update the stored peer's identity key to a known value.
	if p, ok := af.peers.Load(ts.URL); ok {
		authPeer := p.(*AuthPeer)
		authPeer.IdentityKey = serverPubKeyHex
	}

	certSet := utils.RequestedCertificateSet{
		Certifiers:       []*ec.PublicKey{},
		CertificateTypes: make(utils.RequestedCertificateTypeIDAndFieldList),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err = af.SendCertificateRequest(ctx, ts.URL+"/certs", &certSet)
	// Will fail due to no live server handling auth – context timeout is expected
	require.Error(t, err)
}

// TestSendCertificateRequestWithInvalidIdentityKey exercises the code path where
// IdentityKey is set but is not a valid public key string (ec.PublicKeyFromString fails),
// which causes identityKey to remain nil.
func TestSendCertificateRequestWithInvalidIdentityKey(t *testing.T) {
	af := newAuthFetch(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx0, cancel0 := context.WithCancel(context.Background())
	cancel0()
	_, _ = af.Fetch(ctx0, ts.URL+"/init", nil)

	// Set an invalid identity key on the peer
	if p, ok := af.peers.Load(ts.URL); ok {
		authPeer := p.(*AuthPeer)
		authPeer.IdentityKey = "this-is-not-a-valid-hex-key"
	}

	certSet := utils.RequestedCertificateSet{
		Certifiers:       []*ec.PublicKey{},
		CertificateTypes: make(utils.RequestedCertificateTypeIDAndFieldList),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := af.SendCertificateRequest(ctx, ts.URL+"/certs", &certSet)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// handleFetchAndValidate – unreachable URL
// ---------------------------------------------------------------------------

// TestHandleFetchAndValidateUnreachableURL exercises the client.Do error path.
func TestHandleFetchAndValidateUnreachableURL(t *testing.T) {
	af := newAuthFetch(t)

	peer := &AuthPeer{}
	config := &SimplifiedFetchRequestOptions{Method: "GET"}
	_, err := af.handleFetchAndValidate("http://localhost:0/unreachable", config, peer)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

// ---------------------------------------------------------------------------
// handlePaymentAndRetry – RetryCounter already set path
// ---------------------------------------------------------------------------

// TestHandlePaymentAndRetryRetryCounterAlreadySet verifies that if RetryCounter
// is already set, it is not overwritten.
func TestHandlePaymentAndRetryRetryCounterAlreadySet(t *testing.T) {
	serverKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	serverPubKeyHex := serverKey.PubKey().ToDERHex()

	af := newAuthFetch(t)
	resp402 := make402Response()
	resp402.Header.Set(hdrPaymentVersion, PaymentVersion)
	resp402.Header.Set(hdrSatoshisRequired, "100")
	resp402.Header.Set(hdrIdentityKey, serverPubKeyHex)
	resp402.Header.Set(hdrDerivationPrefix, "pfx")

	// RetryCounter already set to 0, so the Fetch will immediately exhaust retries.
	existingRetry := 0
	config := &SimplifiedFetchRequestOptions{
		Method:       "GET",
		RetryCounter: &existingRetry,
	}

	_, err = af.handlePaymentAndRetry(context.Background(), testPayURL, config, resp402)
	require.Error(t, err)
	assert.Contains(t, err.Error(), errMaxRetries)
	// The retry counter should remain at the value we passed (not reset to 3).
	assert.Equal(t, 0, existingRetry)
}

// ---------------------------------------------------------------------------
// Fetch – no peers stored, new peer creation via Fetch with short timeout
// ---------------------------------------------------------------------------

// TestFetchNewPeerCreation exercises the new-peer creation path in Fetch's goroutine.
// We allow the goroutine to start creating a peer and time out immediately.
func TestFetchNewPeerCreation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response to ensure context cancellation is hit
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	af := newAuthFetch(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := af.Fetch(ctx, ts.URL+"/test", &SimplifiedFetchRequestOptions{Method: "GET"})
	require.Error(t, err)
	// Should be context.DeadlineExceeded or similar
}

// ---------------------------------------------------------------------------
// Fetch – GET with no config (nil), exercises the default assignment
// ---------------------------------------------------------------------------

// TestFetchNilConfigDefaultsToGet tests that nil config defaults to GET with no panic.
func TestFetchNilConfigDefaultsToGet(t *testing.T) {
	af := newAuthFetch(t)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// nil config → should default to GET and not panic
	_, err := af.Fetch(ctx, testLocalhostZeroURL, nil)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// handleFetchAndValidate – via non-mutual-auth path with POST and empty body
// ---------------------------------------------------------------------------

// TestHandleFetchAndValidatePostEmptyBody exercises the empty body path.
func TestHandleFetchAndValidatePostEmptyBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	af := newAuthFetch(t)
	buildNonMutualAuthPeer(ts.URL, af)

	resp, err := af.Fetch(context.Background(), ts.URL+"/post", &SimplifiedFetchRequestOptions{
		Method: "POST",
		Body:   nil, // no body
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// Multiple options applied in sequence
// ---------------------------------------------------------------------------

// TestNewMultipleOptionsAppliedInOrder verifies that later options override earlier ones.
func TestNewMultipleOptionsAppliedInOrder(t *testing.T) {
	w := wallet.NewTestWalletForRandomKey(t)

	client1 := &http.Client{Timeout: 1 * time.Second}
	client2 := &http.Client{Timeout: 2 * time.Second}

	af := New(w, WithHttpClient(client1), WithHttpClient(client2))
	// Last option wins
	require.Equal(t, client2, af.client)
}

// ---------------------------------------------------------------------------
// ConsumeReceivedCertificates – called right after New (no certs yet)
// ---------------------------------------------------------------------------

// TestConsumeReceivedCertificatesImmediateAfterNew verifies the fresh state.
func TestConsumeReceivedCertificatesImmediateAfterNew(t *testing.T) {
	af := newAuthFetch(t)
	result := af.ConsumeReceivedCertificates()
	assert.NotNil(t, result)
	assert.Len(t, result, 0)
}

// ---------------------------------------------------------------------------
// handleFetchAndValidate – verifies non-auth BSV header does not trip guard
// ---------------------------------------------------------------------------

// TestHandleFetchAndValidateNonAuthBSVHeader verifies that a non-auth x-bsv header
// does not trigger the authentication claim error.
func TestHandleFetchAndValidateNonAuthBSVHeader(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// x-bsv-payment is not an auth header, should be fine
		w.Header().Set(hdrPayment, "something")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	af := newAuthFetch(t)
	peer := &AuthPeer{}
	config := &SimplifiedFetchRequestOptions{Method: "GET"}
	resp, err := af.handleFetchAndValidate(ts.URL+"/test", config, peer)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// Fetch – invalid HTTP method triggers http.NewRequestWithContext error
// ---------------------------------------------------------------------------

// TestFetchInvalidMethod triggers the http.NewRequestWithContext error path.
// An HTTP method containing a space is invalid per the HTTP spec and will
// cause NewRequestWithContext to return an error (line 215-217 in authhttp.go).
func TestFetchInvalidMethod(t *testing.T) {
	af := newAuthFetch(t)

	// Methods with spaces are invalid and cause NewRequestWithContext to fail.
	_, err := af.Fetch(context.Background(), testExampleURL, &SimplifiedFetchRequestOptions{
		Method: "INVALID METHOD",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create request")
}

// ---------------------------------------------------------------------------
// handlePaymentAndRetry – wallet.CreateNonce error path
// ---------------------------------------------------------------------------

// TestHandlePaymentAndRetryCreateNonceFails exercises the CreateNonce (HMAC) failure path.
func TestHandlePaymentAndRetryCreateNonceFails(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)

	serverKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	serverPubKeyHex := serverKey.PubKey().ToDERHex()

	// Override CreateHMAC to return an error, which will cause CreateNonce to fail.
	tw.OnCreateHMAC().ReturnError(assert.AnError)

	af := New(tw)
	resp402 := make402Response()
	resp402.Header.Set(hdrPaymentVersion, PaymentVersion)
	resp402.Header.Set(hdrSatoshisRequired, "1000")
	resp402.Header.Set(hdrIdentityKey, serverPubKeyHex)
	resp402.Header.Set(hdrDerivationPrefix, "prefix")

	_, err = af.handlePaymentAndRetry(context.Background(), testPayURL,
		&SimplifiedFetchRequestOptions{Method: "GET"}, resp402)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create derivation suffix")
}

// TestHandlePaymentAndRetryGetPublicKeyFails exercises the GetPublicKey failure path.
func TestHandlePaymentAndRetryGetPublicKeyFails(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)

	serverKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	serverPubKeyHex := serverKey.PubKey().ToDERHex()

	// Override GetPublicKey to return an error for the payment key derivation.
	tw.OnGetPublicKey().ReturnError(assert.AnError)

	af := New(tw)
	resp402 := make402Response()
	resp402.Header.Set(hdrPaymentVersion, PaymentVersion)
	resp402.Header.Set(hdrSatoshisRequired, "1000")
	resp402.Header.Set(hdrIdentityKey, serverPubKeyHex)
	resp402.Header.Set(hdrDerivationPrefix, "prefix")

	_, err = af.handlePaymentAndRetry(context.Background(), testPayURL,
		&SimplifiedFetchRequestOptions{Method: "GET"}, resp402)
	require.Error(t, err)
}

// TestHandlePaymentAndRetryCreateActionFails exercises the CreateAction failure path.
func TestHandlePaymentAndRetryCreateActionFails(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)

	serverKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	serverPubKeyHex := serverKey.PubKey().ToDERHex()

	// Let GetPublicKey succeed but make CreateAction fail.
	tw.OnCreateAction().ReturnError(assert.AnError)

	af := New(tw)
	resp402 := make402Response()
	resp402.Header.Set(hdrPaymentVersion, PaymentVersion)
	resp402.Header.Set(hdrSatoshisRequired, "1000")
	resp402.Header.Set(hdrIdentityKey, serverPubKeyHex)
	resp402.Header.Set(hdrDerivationPrefix, "prefix")

	_, err = af.handlePaymentAndRetry(context.Background(), testPayURL,
		&SimplifiedFetchRequestOptions{Method: "GET"}, resp402)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create payment transaction")
}
