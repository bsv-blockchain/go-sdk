package clients

// authhttp_extra2_test.go exercises the certificate-requested listener body
// inside Fetch's goroutine (authhttp.go ~lines 285-303). That closure only runs
// when the server, during the handshake, asks the client for certificates. We
// drive it deterministically by standing up a BRC-31 server whose peer is
// configured with a non-empty CertificatesToRequest, then making the client's
// wallet fail ListCertificates so utils.GetVerifiableCertificates returns an
// error and the listener returns early.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// buildCertRequestingServer stands up a BRC-31 httptest.Server whose auth peer
// requests certificates from every counterparty during the handshake. Because
// only Certifiers (not CertificateTypes) are requested, the server session
// stays authenticated, but its initialResponse still carries a non-empty
// RequestedCertificates set — which triggers the client's certificate-requested
// listener when it processes that response.
func buildCertRequestingServer(t *testing.T) *httptest.Server {
	t.Helper()

	serverKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	serverWallet := wallet.NewTestWallet(t, serverKey)

	serverSM := auth.NewSessionManager()

	ct := newChannelTransport()
	auth.NewPeer(&auth.PeerOptions{
		Wallet:         serverWallet,
		Transport:      ct,
		SessionManager: serverSM,
		CertificatesToRequest: &utils.RequestedCertificateSet{
			Certifiers:       []*ec.PublicKey{serverKey.PubKey()},
			CertificateTypes: make(utils.RequestedCertificateTypeIDAndFieldList),
		},
	})

	mux := http.NewServeMux()
	mux.HandleFunc(wellKnownAuthPath, buildAuthInitHandler(ct))
	// A general-message handler is required for the mux, but the handshake fails
	// before any general message is sent in this test.
	mux.HandleFunc("/", buildGeneralMessageHandler(ct, serverSM, serverWallet, http.StatusOK))

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

// TestFetchCertificateRequestedListenerGetVerifiableCertsError covers the
// certificate-requested listener body up to the GetVerifiableCertificates error
// return: the server asks for certificates, and the client's wallet fails to
// list them, so the listener returns the error and the handshake fails.
func TestFetchCertificateRequestedListenerGetVerifiableCertsError(t *testing.T) {
	ts := buildCertRequestingServer(t)

	clientWallet := wallet.NewTestWalletForRandomKey(t)
	clientWallet.OnListCertificates().ReturnError(errors.New("boom listing certs"))

	af := New(clientWallet, WithoutLogging())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := af.Fetch(ctx, ts.URL+"/data", &SimplifiedFetchRequestOptions{Method: "GET"})
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom listing certs")
}
