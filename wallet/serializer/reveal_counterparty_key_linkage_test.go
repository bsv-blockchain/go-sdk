package serializer

import (
	"github.com/bsv-blockchain/go-sdk/util"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRevealCounterpartyKeyLinkageArgs(t *testing.T) {
	counterparty := tu.GetByte33FromHexString(t, "0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1")
	verifier := tu.GetByte33FromHexString(t, "03b106dae20ae8fca0f4e8983d974c4b583054573eecdcdcfad261c035415ce1ee")

	tests := []struct {
		name string
		args *wallet.RevealCounterpartyKeyLinkageArgs
	}{
		{
			name: "full args",
			args: &wallet.RevealCounterpartyKeyLinkageArgs{
				Counterparty:     counterparty,
				Verifier:         verifier,
				Privileged:       util.BoolPtr(true),
				PrivilegedReason: "test-reason",
			},
		},
		{
			name: "minimal args",
			args: &wallet.RevealCounterpartyKeyLinkageArgs{
				Counterparty: counterparty,
				Verifier:     verifier,
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
	counterparty := tu.GetByte33FromHexString(t, "0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1")
	verifier := tu.GetByte33FromHexString(t, "03b106dae20ae8fca0f4e8983d974c4b583054573eecdcdcfad261c035415ce1ee")

	t.Run("serialize/deserialize", func(t *testing.T) {
		result := &wallet.RevealCounterpartyKeyLinkageResult{
			Prover:                counterparty,
			Verifier:              verifier,
			Counterparty:          counterparty,
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
