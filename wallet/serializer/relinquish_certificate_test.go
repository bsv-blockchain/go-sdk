package serializer

import (
	"testing"

	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestRelinquishCertificateArgs(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.RelinquishCertificateArgs
	}{{
		name: "full args",
		args: &wallet.RelinquishCertificateArgs{
			Type:         [32]byte{1},
			SerialNumber: [32]byte{2},
			Certifier:    tu.GetPKFromBytes([]byte{3}),
		},
	}, {
		name: "minimal args",
		args: &wallet.RelinquishCertificateArgs{
			Type:         [32]byte{4},
			SerialNumber: [32]byte{5},
			Certifier:    tu.GetPKFromBytes([]byte{6}),
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeRelinquishCertificateArgs(tt.args)
			require.NoError(t, err, "serializing RelinquishCertificateArgs should not error")

			// Test deserialization
			got, err := DeserializeRelinquishCertificateArgs(data)
			require.NoError(t, err, "deserializing RelinquishCertificateArgs should not error")

			// Compare results
			require.Equal(t, tt.args, got, "deserialized args should match original args")
		})
	}
}

func TestRelinquishCertificateResult(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		result := &wallet.RelinquishCertificateResult{Relinquished: true}
		data, err := SerializeRelinquishCertificateResult(result)
		require.NoError(t, err, "serializing RelinquishCertificateResult should not error")

		got, err := DeserializeRelinquishCertificateResult(data)
		require.NoError(t, err, "deserializing RelinquishCertificateResult should not error")
		require.Equal(t, result, got, "deserialized result should match original result")
	})
}
