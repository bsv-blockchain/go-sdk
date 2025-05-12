package serializer

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestVerifyHmacArgs(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.VerifyHmacArgs
	}{{
		name: "full args",
		args: &wallet.VerifyHmacArgs{
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
			Hmac: make([]byte, 32), // 32 byte HMAC
		},
	}, {
		name: "minimal args",
		args: &wallet.VerifyHmacArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelSilent,
					Protocol:      "minimal",
				},
				KeyID: "minimal-key",
			},
			Data: []byte{1},
			Hmac: make([]byte, 32),
		},
	}, {
		name: "empty data",
		args: &wallet.VerifyHmacArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelSilent,
					Protocol:      "empty-data",
				},
				KeyID: "empty-key",
			},
			Data: []byte{},
			Hmac: make([]byte, 32),
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeVerifyHmacArgs(tt.args)
			require.NoError(t, err)

			// Test deserialization
			got, err := DeserializeVerifyHmacArgs(data)
			require.NoError(t, err)

			// Compare results
			require.Equal(t, tt.args, got)
		})
	}
}

func TestVerifyHmacResult(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		result := &wallet.VerifyHmacResult{Valid: true}
		data, err := SerializeVerifyHmacResult(result)
		require.NoError(t, err)

		got, err := DeserializeVerifyHmacResult(data)
		require.NoError(t, err)
		require.Equal(t, result, got)
	})

	t.Run("error byte", func(t *testing.T) {
		data := []byte{1} // error byte = 1 (failure)
		_, err := DeserializeVerifyHmacResult(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "verifyHmac failed with error byte 1")
	})
}
