package serializer

import (
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRevealCounterpartyKeyLinkageArgs(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.RevealCounterpartyKeyLinkageArgs
	}{
		{
			name: "full args",
			args: &wallet.RevealCounterpartyKeyLinkageArgs{
				Counterparty:     "02c96db2304d2b73e8f79a9479d1e9e0e1e8b0f3a9a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
				Verifier:         "03c96db2304d2b73e8f79a9479d1e9e0e1e8b0f3a9a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
				Privileged:       util.BoolPtr(true),
				PrivilegedReason: "test-reason",
			},
		},
		{
			name: "minimal args",
			args: &wallet.RevealCounterpartyKeyLinkageArgs{
				Counterparty: "02c96db2304d2b73e8f79a9479d1e9e0e1e8b0f3a9a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
				Verifier:     "03c96db2304d2b73e8f79a9479d1e9e0e1e8b0f3a9a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeRevealCounterpartyKeyLinkageArgs(tt.args)
			require.NoError(t, err, "serializing RevealCounterpartyKeyLinkageArgs should not error")

			// Test deserialization
			got, err := DeserializeRevealCounterpartyKeyLinkageArgs(data)
			require.NoError(t, err, "deserializing RevealCounterpartyKeyLinkageArgs should not error")

			// Compare results
			require.Equal(t, tt.args, got, "deserialized args should match original args")
		})
	}
}

func TestRevealCounterpartyKeyLinkageResult(t *testing.T) {
	t.Run("serialize/deserialize", func(t *testing.T) {
		result := &wallet.RevealCounterpartyKeyLinkageResult{
			Prover:                "02c96db2304d2b73e8f79a9479d1e9e0e1e8b0f3a9a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
			Verifier:              "03c96db2304d2b73e8f79a9479d1e9e0e1e8b0f3a9a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
			Counterparty:          "02c96db2304d2b73e8f79a9479d1e9e0e1e8b0f3a9a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
			RevelationTime:        "2023-01-01T00:00:00Z",
			EncryptedLinkage:      []byte{1, 2, 3, 4},
			EncryptedLinkageProof: []byte{5, 6, 7, 8},
		}

		data, err := SerializeRevealCounterpartyKeyLinkageResult(result)
		require.NoError(t, err, "serializing RevealCounterpartyKeyLinkageResult should not error")

		got, err := DeserializeRevealCounterpartyKeyLinkageResult(data)
		require.NoError(t, err, "deserializing RevealCounterpartyKeyLinkageResult should not error")
		require.Equal(t, result, got, "deserialized result should match original result")
	})
}
