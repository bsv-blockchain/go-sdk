package serializer

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCreateSignatureArgs(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.CreateSignatureArgs
	}{{
		name: "full args with data",
		args: &wallet.CreateSignatureArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryApp,
					Protocol:      "test-protocol",
				},
				KeyID:            "test-key",
				Counterparty:     wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
				Privileged:       true,
				PrivilegedReason: "test-reason",
				SeekPermission:   true,
			},
			Data: []byte{1, 2, 3, 4},
		},
	}, {
		name: "full args with hash",
		args: &wallet.CreateSignatureArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
					Protocol:      "test-hash",
				},
				KeyID: "hash-key",
			},
			HashToDirectlySign: make([]byte, 32),
		},
	}, {
		name: "minimal args",
		args: &wallet.CreateSignatureArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelSilent,
					Protocol:      "minimal",
				},
				KeyID: "min-key",
			},
			Data: []byte{1},
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeCreateSignatureArgs(tt.args)
			require.NoError(t, err, "serializing CreateSignatureArgs should not error")

			// Test deserialization
			got, err := DeserializeCreateSignatureArgs(data)
			require.NoError(t, err, "deserializing CreateSignatureArgs should not error")

			// Compare results
			require.Equal(t, tt.args, got, "deserialized args should match original args")
		})
	}
}

func TestCreateSignatureResult(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		result := &wallet.CreateSignatureResult{Signature: newTestSignature(t)}
		data, err := SerializeCreateSignatureResult(result)
		require.NoError(t, err, "serializing CreateSignatureResult should not error")

		got, err := DeserializeCreateSignatureResult(data)
		require.NoError(t, err, "deserializing CreateSignatureResult should not error")
		require.Equal(t, result, got, "deserialized result should match original result")
	})

	t.Run("error byte", func(t *testing.T) {
		data := []byte{1} // error byte = 1 (failure)
		_, err := DeserializeCreateSignatureResult(data)
		require.Error(t, err, "deserializing with error byte should produce an error")
		require.Contains(t, err.Error(), "createSignature failed with error byte 1", "error message should indicate failure and error byte")
	})
}
