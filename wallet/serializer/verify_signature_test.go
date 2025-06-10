package serializer

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestVerifySignatureArgs(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.VerifySignatureArgs
	}{{
		name: "full args with data",
		args: &wallet.VerifySignatureArgs{
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
			ForSelf:              true,
			Signature:            newTestSignature(t),
			Data:                 []byte{5, 6, 7, 8},
			HashToDirectlyVerify: nil,
		},
	}, {
		name: "full args with hash",
		args: &wallet.VerifySignatureArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
					Protocol:      "test-hash",
				},
				KeyID: "hash-key",
			},
			Signature:            newTestSignature(t),
			HashToDirectlyVerify: make([]byte, 32),
		},
	}, {
		name: "minimal args",
		args: &wallet.VerifySignatureArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelSilent,
					Protocol:      "minimal",
				},
				KeyID: "min-key",
			},
			Signature: newTestSignature(t),
			Data:      []byte{1},
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeVerifySignatureArgs(tt.args)
			require.NoError(t, err, "serializing VerifySignatureArgs should not error")

			// Test deserialization
			got, err := DeserializeVerifySignatureArgs(data)
			require.NoError(t, err, "deserializing VerifySignatureArgs should not error")

			// Compare results
			require.Equal(t, tt.args, got, "deserialized args should match original args")
		})
	}
}

func TestVerifySignatureResult(t *testing.T) {
	t.Run("valid signature", func(t *testing.T) {
		result := &wallet.VerifySignatureResult{Valid: true}
		data, err := SerializeVerifySignatureResult(result)
		require.NoError(t, err, "serializing valid VerifySignatureResult should not error")

		got, err := DeserializeVerifySignatureResult(data)
		require.NoError(t, err, "deserializing valid VerifySignatureResult should not error")
		require.Equal(t, result, got, "deserialized valid result should match original result")
	})

	t.Run("invalid signature", func(t *testing.T) {
		result := &wallet.VerifySignatureResult{Valid: false}
		data, err := SerializeVerifySignatureResult(result)
		require.NoError(t, err, "serializing invalid VerifySignatureResult should not error")

		got, err := DeserializeVerifySignatureResult(data)
		require.NoError(t, err, "deserializing invalid VerifySignatureResult should not error")
		require.Equal(t, result, got, "deserialized invalid result should match original result")
	})

	t.Run("error byte", func(t *testing.T) {
		data := []byte{1} // error byte = 1 (failure)
		_, err := DeserializeVerifySignatureResult(data)
		require.Error(t, err, "deserializing with error byte should produce an error")
		require.Contains(t, err.Error(), "verifySignature failed with error byte 1", "error message should indicate failure and error byte")
	})
}
