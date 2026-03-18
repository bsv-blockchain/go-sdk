package substrates

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestHTTPWalletJSONGetPublicKey(t *testing.T) {
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/getPublicKey", r.URL.Path)

		// Don't decode args - EncryptionArgs has a custom protocolID format
		resp := wallet.GetPublicKeyResult{PublicKey: privKey.PubKey()}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(&resp)
		require.NoError(t, err)
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)
	result, err := client.GetPublicKey(t.Context(), wallet.GetPublicKeyArgs{IdentityKey: true})
	require.NoError(t, err)
	require.NotNil(t, result.PublicKey)
}
