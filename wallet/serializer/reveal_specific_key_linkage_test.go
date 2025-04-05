package serializer

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)


func TestRevealSpecificKeyLinkageArgs(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.RevealSpecificKeyLinkageArgs
	}{
		{
			name: "full args",
			args: &wallet.RevealSpecificKeyLinkageArgs{
				Counterparty: newCounterparty(t, "03d4f6b2d5e6c8a9b0f7e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687"),
				Verifier:     "02c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1",
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevel(1),
					Protocol:      "test-protocol",
				},
				KeyID:            "test-key-id",
				Privileged:       boolPtr(true),
				PrivilegedReason: "admin request",
			},
		},
		{
			name: "minimal args",
			args: &wallet.RevealSpecificKeyLinkageArgs{
				Counterparty: newCounterparty(t, "03d4f6b2d5e6c8a9b0f7e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687"),
				Verifier:     "02c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1",
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
			require.NoError(t, err)

			// Test deserialization
			got, err := DeserializeRevealSpecificKeyLinkageArgs(data)
			require.NoError(t, err)

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
				Prover:       fromHex(t, "03d4f6b2d5e6c8a9b0f7e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687"),
				Verifier:     fromHex(t, "02c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1"),
				Counterparty: newCounterparty(t, "03f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687"),
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
				Prover:       fromHex(t, "03d4f6b2d5e6c8a9b0f7e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687"),
				Verifier:     fromHex(t, "02c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1"),
				Counterparty: newCounterparty(t, "03f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687"),
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
			require.NoError(t, err)

			// Test deserialization
			got, err := DeserializeRevealSpecificKeyLinkageResult(data)
			require.NoError(t, err)

			// Compare results
			require.Equal(t, tt.result, got)
		})
	}
}
