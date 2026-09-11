package substrates

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func TestHTTPWalletJSONGetPublicKey(t *testing.T) {
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/getPublicKey", r.URL.Path)

		// Don't decode args - EncryptionArgs has a custom protocolID format
		resp := wallet.GetPublicKeyResult{PublicKey: privKey.PubKey()}
		w.Header().Set("Content-Type", "application/json")
		encodeErr := json.NewEncoder(w).Encode(&resp)
		assert.NoError(t, encodeErr)
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)
	result, err := client.GetPublicKey(t.Context(), wallet.GetPublicKeyArgs{IdentityKey: true})
	require.NoError(t, err)
	require.NotNil(t, result.PublicKey)
}

// TestHTTPWalletJSONAPIErrorBranches drives every wallet method against a server
// that always returns HTTP 500, exercising each method's "api error" return path.
func TestHTTPWalletJSONAPIErrorBranches(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"boom"}`))
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)
	ctx := context.Background()

	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	sig, err := privKey.Sign(make([]byte, 32))
	require.NoError(t, err)

	checks := map[string]func() error{
		"CreateAction":      func() error { _, e := client.CreateAction(ctx, wallet.CreateActionArgs{}); return e },
		"SignAction":        func() error { _, e := client.SignAction(ctx, &wallet.SignActionArgs{}); return e },
		"AbortAction":       func() error { _, e := client.AbortAction(ctx, wallet.AbortActionArgs{}); return e },
		"ListActions":       func() error { _, e := client.ListActions(ctx, wallet.ListActionsArgs{}); return e },
		"InternalizeAction": func() error { _, e := client.InternalizeAction(ctx, wallet.InternalizeActionArgs{}); return e },
		"ListOutputs":       func() error { _, e := client.ListOutputs(ctx, wallet.ListOutputsArgs{}); return e },
		"RelinquishOutput":  func() error { _, e := client.RelinquishOutput(ctx, &wallet.RelinquishOutputArgs{}); return e },
		"GetPublicKey":      func() error { _, e := client.GetPublicKey(ctx, wallet.GetPublicKeyArgs{IdentityKey: true}); return e },
		"RevealCounterpartyKeyLinkage": func() error {
			_, e := client.RevealCounterpartyKeyLinkage(ctx, wallet.RevealCounterpartyKeyLinkageArgs{})
			return e
		},
		"RevealSpecificKeyLinkage": func() error {
			_, e := client.RevealSpecificKeyLinkage(ctx, wallet.RevealSpecificKeyLinkageArgs{})
			return e
		},
		"Encrypt":    func() error { _, e := client.Encrypt(ctx, wallet.EncryptArgs{}); return e },
		"Decrypt":    func() error { _, e := client.Decrypt(ctx, wallet.DecryptArgs{}); return e },
		"CreateHMAC": func() error { _, e := client.CreateHMAC(ctx, wallet.CreateHMACArgs{}); return e },
		"VerifyHMAC": func() error { _, e := client.VerifyHMAC(ctx, wallet.VerifyHMACArgs{}); return e },
		"CreateSignature": func() error {
			_, e := client.CreateSignature(ctx, wallet.CreateSignatureArgs{})
			return e
		},
		"VerifySignature": func() error {
			_, e := client.VerifySignature(ctx, wallet.VerifySignatureArgs{Signature: sig})
			return e
		},
		"AcquireCertificate": func() error {
			_, e := client.AcquireCertificate(ctx, &wallet.AcquireCertificateArgs{})
			return e
		},
		"ListCertificates": func() error { _, e := client.ListCertificates(ctx, wallet.ListCertificatesArgs{}); return e },
		"ProveCertificate": func() error {
			_, e := client.ProveCertificate(ctx, &wallet.ProveCertificateArgs{})
			return e
		},
		"RelinquishCertificate": func() error {
			_, e := client.RelinquishCertificate(ctx, &wallet.RelinquishCertificateArgs{})
			return e
		},
		"DiscoverByIdentityKey": func() error {
			_, e := client.DiscoverByIdentityKey(ctx, &wallet.DiscoverByIdentityKeyArgs{})
			return e
		},
		"DiscoverByAttributes": func() error {
			_, e := client.DiscoverByAttributes(ctx, wallet.DiscoverByAttributesArgs{})
			return e
		},
		"IsAuthenticated":       func() error { _, e := client.IsAuthenticated(ctx, nil); return e },
		"WaitForAuthentication": func() error { _, e := client.WaitForAuthentication(ctx, nil); return e },
		"GetHeight":             func() error { _, e := client.GetHeight(ctx, nil); return e },
		"GetHeaderForHeight":    func() error { _, e := client.GetHeaderForHeight(ctx, wallet.GetHeaderArgs{}); return e },
		"GetNetwork":            func() error { _, e := client.GetNetwork(ctx, nil); return e },
		"GetVersion":            func() error { _, e := client.GetVersion(ctx, nil); return e },
	}

	for name, fn := range checks {
		t.Run(name, func(t *testing.T) {
			err := fn()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "500")
		})
	}
}
