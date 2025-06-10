package serializer

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/v2/util"
	tu "github.com/bsv-blockchain/go-sdk/v2/util/test_util"
	"github.com/bsv-blockchain/go-sdk/v2/wallet"
	"github.com/stretchr/testify/require"
)

func TestRevealSpecificKeyLinkageArgs(t *testing.T) {
	verifier := tu.GetPKFromHex(t, "02c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2")

	tests := []struct {
		name string
		args *wallet.RevealSpecificKeyLinkageArgs
	}{
		{
			name: "full args",
			args: &wallet.RevealSpecificKeyLinkageArgs{
				Counterparty: newCounterparty(t, "03d4f6b2d5e6c8a9b0f7e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687"),
				Verifier:     verifier,
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevel(1),
					Protocol:      "test-protocol",
				},
				KeyID:            "test-key-id",
				Privileged:       util.BoolPtr(true),
				PrivilegedReason: "admin request",
			},
		},
		{
			name: "minimal args",
			args: &wallet.RevealSpecificKeyLinkageArgs{
				Counterparty: newCounterparty(t, "03d4f6b2d5e6c8a9b0f7e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687"),
				Verifier:     verifier,
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevel(0),
					Protocol:      "minimal",
				},
				KeyID: "min-key",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeRevealSpecificKeyLinkageArgs(tt.args)
			require.NoError(t, err, "serializing RevealSpecificKeyLinkageArgs should not error")

			// Test deserialization
			got, err := DeserializeRevealSpecificKeyLinkageArgs(data)
			require.NoError(t, err, "deserializing RevealSpecificKeyLinkageArgs should not error")

			// Compare results
			require.Equal(t, tt.args, got)
		})
	}
}

func TestRevealSpecificKeyLinkageResult(t *testing.T) {
	tests := []struct {
		name   string
		result *wallet.RevealSpecificKeyLinkageResult
	}{
		{
			name: "full result",
			result: &wallet.RevealSpecificKeyLinkageResult{
				Prover:       tu.GetPKFromHex(t, "03d4f6b2d5e6c8a9b0f7e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687"),
				Verifier:     tu.GetPKFromHex(t, "02c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2"),
				Counterparty: tu.GetPKFromHex(t, "03f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687"),
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevel(1),
					Protocol:      "test-protocol",
				},
				KeyID:                 "test-key-id",
				EncryptedLinkage:      []byte{1, 2, 3, 4},
				EncryptedLinkageProof: []byte{5, 6, 7, 8},
				ProofType:             1,
			},
		},
		{
			name: "minimal result",
			result: &wallet.RevealSpecificKeyLinkageResult{
				Prover:       tu.GetPKFromHex(t, "03d4f6b2d5e6c8a9b0f7e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687"),
				Verifier:     tu.GetPKFromHex(t, "02c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2"),
				Counterparty: tu.GetPKFromHex(t, "03f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687"),
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevel(0),
					Protocol:      "minimal",
				},
				KeyID:     "min-key",
				ProofType: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeRevealSpecificKeyLinkageResult(tt.result)
			require.NoError(t, err, "serializing RevealSpecificKeyLinkageResult should not error")

			// Test deserialization
			got, err := DeserializeRevealSpecificKeyLinkageResult(data)
			require.NoError(t, err, "deserializing RevealSpecificKeyLinkageResult should not error")

			// Compare results
			require.Equal(t, tt.result, got)
		})
	}
}
