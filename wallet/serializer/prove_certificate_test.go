package serializer

import (
	"encoding/base64"
	"github.com/bsv-blockchain/go-sdk/util"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestProveCertificateArgs(t *testing.T) {
	pk, err := ec.NewPrivateKey()
	require.NoError(t, err, "generating private key should not error")
	tests := []struct {
		name string
		args *wallet.ProveCertificateArgs
	}{{
		name: "full args",
		args: &wallet.ProveCertificateArgs{
			Certificate: wallet.Certificate{
				Type:               [32]byte{0x1},
				Subject:            pk.PubKey(),
				SerialNumber:       [32]byte{0x2},
				Certifier:          pk.PubKey(),
				RevocationOutpoint: tu.WalletOutpointFromString(t, "a755810c21e17183ff6db6685f0de239fd3a0a3c0d4ba7773b0b0d1748541e2b.1"),
				Signature:          make([]byte, 64),
				Fields: map[string]string{
					"field1": "value1",
					"field2": "value2",
				},
			},
			FieldsToReveal:   []string{"field1"},
			Privileged:       util.BoolPtr(true),
			PrivilegedReason: "test-reason",
		},
	}, {
		name: "minimal args",
		args: &wallet.ProveCertificateArgs{
			Certificate: wallet.Certificate{
				Type:               [32]byte{0x1},
				Subject:            pk.PubKey(),
				SerialNumber:       [32]byte{0x2},
				Certifier:          pk.PubKey(),
				RevocationOutpoint: tu.WalletOutpointFromString(t, "0000000000000000000000000000000000000000000000000000000000000000.0"),
				Signature:          make([]byte, 64),
			},
			FieldsToReveal: []string{},
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeProveCertificateArgs(tt.args)
			require.NoError(t, err, "serializing ProveCertificateArgs should not error")

			// Test deserialization
			got, err := DeserializeProveCertificateArgs(data)
			require.NoError(t, err, "deserializing ProveCertificateArgs should not error")

			// Compare results
			require.Equal(t, tt.args, got, "deserialized args should match original args")
		})
	}
}

func TestProveCertificateResult(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		result := &wallet.ProveCertificateResult{
			KeyringForVerifier: map[string]string{
				"field1": base64.StdEncoding.EncodeToString([]byte("value1")),
			},
		}
		data, err := SerializeProveCertificateResult(result)
		require.NoError(t, err, "serializing ProveCertificateResult should not error")

		got, err := DeserializeProveCertificateResult(data)
		require.NoError(t, err, "deserializing ProveCertificateResult should not error")
		require.Equal(t, result, got, "deserialized result should match original result")
	})

	t.Run("error byte", func(t *testing.T) {
		data := []byte{1} // error byte = 1 (failure)
		_, err := DeserializeProveCertificateResult(data)
		require.Error(t, err, "deserializing with error byte should produce an error")
		require.Contains(t, err.Error(), "proveCertificate failed with error byte 1", "error message should indicate failure and error byte")
	})
}
