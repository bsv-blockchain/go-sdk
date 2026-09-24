package wallet_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// TestRevealCounterpartyKeyLinkageConformance runs
// wallet/brc100/revealcounterpartykeylinkage.json. Every vector in this file
// documents an error case (RevealCounterpartyKeyLinkageArgs.Counterparty is a
// bare public key with no "self"/"anyone" sentinel, so a vector's
// counterparty="self"/"anyone" or malformed-hex string can't even decode).
func TestRevealCounterpartyKeyLinkageConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/revealcounterpartykeylinkage.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		in := decodeVectorInput(t, v)
		pw := newProtoWallet(t, in.RootKey)
		wantErr := vectorExpectsError(t, v)

		var args wallet.RevealCounterpartyKeyLinkageArgs
		if err := json.Unmarshal(in.Args, &args); err != nil {
			require.True(t, wantErr, "%s: unexpected arg decode error: %v", v.ID, err)
			return
		}

		_, err := pw.RevealCounterpartyKeyLinkage(context.Background(), args, in.Originator)
		if wantErr {
			require.Error(t, err, "%s: expected an error", v.ID)
			return
		}
		require.NoError(t, err, v.ID)
	})
}

// TestRevealSpecificKeyLinkageConformance runs
// wallet/brc100/revealspecifickeylinkage.json. EncryptedLinkage /
// EncryptedLinkageProof embed a randomly-IV'd ciphertext (ProtoWallet.Encrypt),
// so — matching the ts-stack reference dispatcher, which only checks their
// presence and never compares their bytes — we assert presence for those two
// fields and exact equality for the deterministic ones.
func TestRevealSpecificKeyLinkageConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/revealspecifickeylinkage.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		in := decodeVectorInput(t, v)
		pw := newProtoWallet(t, in.RootKey)
		wantErr := vectorExpectsError(t, v)

		var args wallet.RevealSpecificKeyLinkageArgs
		if err := json.Unmarshal(in.Args, &args); err != nil {
			require.True(t, wantErr, "%s: unexpected arg decode error: %v", v.ID, err)
			return
		}

		result, err := pw.RevealSpecificKeyLinkage(context.Background(), args, in.Originator)
		if wantErr {
			require.Error(t, err, "%s: expected an error", v.ID)
			return
		}
		require.NoError(t, err, v.ID)
		require.NotEmpty(t, result.EncryptedLinkage, v.ID)
		require.NotEmpty(t, result.EncryptedLinkageProof, v.ID)

		var expected struct {
			Prover       string          `json:"prover"`
			Verifier     string          `json:"verifier"`
			Counterparty string          `json:"counterparty"`
			ProtocolID   wallet.Protocol `json:"protocolID"`
			KeyID        string          `json:"keyID"`
		}
		v.DecodeExpected(t, &expected)
		if expected.Prover != "" {
			require.Equal(t, expected.Prover, result.Prover.ToDERHex(), v.ID)
		}
		if expected.Verifier != "" {
			require.Equal(t, expected.Verifier, result.Verifier.ToDERHex(), v.ID)
		}
		if expected.Counterparty != "" {
			require.Equal(t, expected.Counterparty, result.Counterparty.ToDERHex(), v.ID)
		}
		if expected.ProtocolID.Protocol != "" {
			require.Equal(t, expected.ProtocolID, result.ProtocolID, v.ID)
		}
		if expected.KeyID != "" {
			require.Equal(t, expected.KeyID, result.KeyID, v.ID)
		}
	})
}
