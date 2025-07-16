package serializer

import (
	"encoding/base64"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestProveCertificateArgs(t *testing.T) {
	pk, err := ec.NewPrivateKey()
	require.NoError(t, err, "generating private key should not error")
	sig := tu.GetSigFromHex(t, "3045022100a6f09ee70382ab364f3f6b040aebb8fe7a51dbc3b4c99cfeb2f7756432162833022067349b91a6319345996faddf36d1b2f3a502e4ae002205f9d2db85474f9aed5a")
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
				RevocationOutpoint: tu.OutpointFromString(t, "a755810c21e17183ff6db6685f0de239fd3a0a3c0d4ba7773b0b0d1748541e2b.1"),
				Signature:          sig,
				Fields: map[string]string{
					"field1": "value1",
					"field2": "value2",
				},
			},
			FieldsToReveal:   []string{"field1"},
			Verifier:         pk.PubKey(),
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
				RevocationOutpoint: tu.OutpointFromString(t, "0000000000000000000000000000000000000000000000000000000000000000.0"),
				Signature:          sig,
			},
			FieldsToReveal: []string{},
			Verifier:       pk.PubKey(),
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
}
