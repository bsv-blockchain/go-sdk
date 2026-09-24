package wallet_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// TestPaymentDerivationConformance runs
// wallet/brc29/payment-derivation.json. This exercises the same
// ProtoWallet.GetPublicKey path as wallet.brc100.getpublickey, but with
// BRC-29 payment protocol IDs and a real (non-self) counterparty, so it
// specifically covers the BRC-42/BRC-29 output-key derivation.
func TestPaymentDerivationConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc29/payment-derivation.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		in := decodeVectorInput(t, v)
		pw := newProtoWallet(t, in.RootKey)

		var args wallet.GetPublicKeyArgs
		require.NoError(t, json.Unmarshal(in.Args, &args), v.ID)

		result, err := pw.GetPublicKey(context.Background(), args, in.Originator)
		require.NoError(t, err, v.ID)
		require.NotNil(t, result.PublicKey, v.ID)

		var expected struct {
			PublicKey string `json:"publicKey"`
		}
		v.DecodeExpected(t, &expected)
		require.NotEmpty(t, expected.PublicKey, "%s: fixture must document the derived key", v.ID)
		require.Equal(t, expected.PublicKey, result.PublicKey.ToDERHex(), v.ID)
	})
}
