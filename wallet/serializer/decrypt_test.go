package serializer

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDecryptArgs(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.DecryptArgs
	}{{
		name: "full args",
		args: &wallet.DecryptArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryApp,
					Protocol:      "test-protocol",
				},
				KeyID:            "test-key",
				SeekPermission:   true,
				PrivilegedReason: "test-reason",
				Counterparty:     newCounterparty(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
			},
			Ciphertext: []byte{1, 2, 3, 4},
		},
	}, {
		name: "minimal args",
		args: &wallet.DecryptArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				KeyID: "min-key",
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelSilent,
					Protocol:      "minimal",
				},
			},
			Ciphertext: []byte{5, 6},
		},
	}, {
		name: "self counterparty",
		args: &wallet.DecryptArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				KeyID: "self-key",
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
					Protocol:      "self",
				},
				Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
			},
			Ciphertext: []byte{7, 8, 9},
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeDecryptArgs(tt.args)
			require.NoError(t, err)

			// Test deserialization
			got, err := DeserializeDecryptArgs(data)
			require.NoError(t, err)

			// Compare results
			require.Equal(t, tt.args, got)
		})
	}
}

func TestDecryptResult(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		result := &wallet.DecryptResult{Plaintext: []byte{1, 2, 3}}
		data, err := SerializeDecryptResult(result)
		require.NoError(t, err)

		got, err := DeserializeDecryptResult(data)
		require.NoError(t, err)
		require.Equal(t, result, got)
	})
}
