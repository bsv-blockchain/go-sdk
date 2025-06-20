package serializer

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCreateHMACArgs(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.CreateHMACArgs
	}{{
		name: "full args",
		args: &wallet.CreateHMACArgs{
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
		name: "minimal args",
		args: &wallet.CreateHMACArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelSilent,
					Protocol:      "minimal",
				},
				KeyID: "minimal-key",
			},
			Data: []byte{1},
		},
	}, {
		name: "empty data",
		args: &wallet.CreateHMACArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelSilent,
					Protocol:      "empty-data",
				},
				KeyID: "empty-key",
			},
			Data: []byte{},
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeCreateHMACArgs(tt.args)
			require.NoError(t, err)

			// Test deserialization
			got, err := DeserializeCreateHMACArgs(data)
			require.NoError(t, err)

			// Compare results
			require.Equal(t, tt.args, got)
		})
	}
}

func TestCreateHMACResult(t *testing.T) {
	t.Run("serialize/deserialize", func(t *testing.T) {
		result := &wallet.CreateHMACResult{HMAC: []byte{1, 2, 3, 4}}
		data, err := SerializeCreateHMACResult(result)
		require.NoError(t, err)

		got, err := DeserializeCreateHMACResult(data)
		require.NoError(t, err)
		require.Equal(t, result, got)
	})
}
