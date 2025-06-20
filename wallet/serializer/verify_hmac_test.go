package serializer

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestVerifyHMACArgs(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.VerifyHMACArgs
	}{{
		name: "full args",
		args: &wallet.VerifyHMACArgs{
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
			HMAC: make([]byte, 32), // 32 byte HMAC
		},
	}, {
		name: "minimal args",
		args: &wallet.VerifyHMACArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelSilent,
					Protocol:      "minimal",
				},
				KeyID: "minimal-key",
			},
			Data: []byte{1},
			HMAC: make([]byte, 32),
		},
	}, {
		name: "empty data",
		args: &wallet.VerifyHMACArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelSilent,
					Protocol:      "empty-data",
				},
				KeyID: "empty-key",
			},
			Data: []byte{},
			HMAC: make([]byte, 32),
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeVerifyHMACArgs(tt.args)
			require.NoError(t, err)

			// Test deserialization
			got, err := DeserializeVerifyHMACArgs(data)
			require.NoError(t, err)

			// Compare results
			require.Equal(t, tt.args, got)
		})
	}
}

func TestVerifyHMACResult(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		result := &wallet.VerifyHMACResult{Valid: true}
		data, err := SerializeVerifyHMACResult(result)
		require.NoError(t, err)

		got, err := DeserializeVerifyHMACResult(data)
		require.NoError(t, err)
		require.Equal(t, result, got)
	})

	t.Run("error byte", func(t *testing.T) {
		data := []byte{1} // error byte = 1 (failure)
		_, err := DeserializeVerifyHMACResult(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "verifyHMAC failed with error byte 1")
	})
}
