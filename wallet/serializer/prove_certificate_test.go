package serializer

import (
	"encoding/base64"
	"encoding/hex"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestProveCertificateArgs(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.ProveCertificateArgs
	}{{
		name: "full args",
		args: &wallet.ProveCertificateArgs{
			Certificate: wallet.Certificate{
				Type:         base64.StdEncoding.EncodeToString(make([]byte, SizeType)),
				Subject:      hex.EncodeToString(make([]byte, SizeCertifier)),
				SerialNumber: base64.StdEncoding.EncodeToString(make([]byte, SizeType)),
				Certifier:    hex.EncodeToString(make([]byte, SizeCertifier)),
				RevocationOutpoint: "0000000000000000000000000000000000000000000000000000000000000000.0",
				Signature:    hex.EncodeToString(make([]byte, 64)),
				Fields: map[string]string{
					"field1": "value1",
					"field2": "value2",
				},
			},
			FieldsToReveal: []string{"field1"},
			Verifier:       hex.EncodeToString(make([]byte, SizeCertifier)),
			Privileged:     boolPtr(true),
			PrivilegedReason: "test-reason",
		},
	}, {
		name: "minimal args",
		args: &wallet.ProveCertificateArgs{
			Certificate: wallet.Certificate{
				Type:         base64.StdEncoding.EncodeToString(make([]byte, SizeType)),
				Subject:      hex.EncodeToString(make([]byte, SizeCertifier)),
				SerialNumber: base64.StdEncoding.EncodeToString(make([]byte, SizeType)),
				Certifier:    hex.EncodeToString(make([]byte, SizeCertifier)),
				RevocationOutpoint: "0000000000000000000000000000000000000000000000000000000000000000.0",
				Signature:    hex.EncodeToString(make([]byte, 64)),
			},
			FieldsToReveal: []string{},
			Verifier:       hex.EncodeToString(make([]byte, SizeCertifier)),
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeProveCertificateArgs(tt.args)
			require.NoError(t, err)

			// Test deserialization
			got, err := DeserializeProveCertificateArgs(data)
			require.NoError(t, err)

			// Compare results
			require.Equal(t, tt.args, got)
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
		require.NoError(t, err)

		got, err := DeserializeProveCertificateResult(data)
		require.NoError(t, err)
		require.Equal(t, result, got)
	})

	t.Run("error byte", func(t *testing.T) {
		data := []byte{1} // error byte = 1 (failure)
		_, err := DeserializeProveCertificateResult(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "proveCertificate failed with error byte 1")
	})
}
