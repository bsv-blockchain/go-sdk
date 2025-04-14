package serializer

import (
	"encoding/base64"
	"encoding/hex"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRelinquishCertificateArgs(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.RelinquishCertificateArgs
	}{{
		name: "full args",
		args: &wallet.RelinquishCertificateArgs{
			Type:         base64.StdEncoding.EncodeToString(make([]byte, SizeType)),
			SerialNumber: base64.StdEncoding.EncodeToString(make([]byte, SizeSerial)),
			Certifier:    hex.EncodeToString(make([]byte, SizeCertifier)),
		},
	}, {
		name: "minimal args",
		args: &wallet.RelinquishCertificateArgs{
			Type:         base64.StdEncoding.EncodeToString(make([]byte, SizeType)),
			SerialNumber: base64.StdEncoding.EncodeToString(make([]byte, SizeSerial)),
			Certifier:    hex.EncodeToString(make([]byte, SizeCertifier)),
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeRelinquishCertificateArgs(tt.args)
			require.NoError(t, err)

			// Test deserialization
			got, err := DeserializeRelinquishCertificateArgs(data)
			require.NoError(t, err)

			// Compare results
			require.Equal(t, tt.args, got)
		})
	}
}

func TestRelinquishCertificateResult(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		result := &wallet.RelinquishCertificateResult{Relinquished: true}
		data, err := SerializeRelinquishCertificateResult(result)
		require.NoError(t, err)

		got, err := DeserializeRelinquishCertificateResult(data)
		require.NoError(t, err)
		require.Equal(t, result, got)
	})

	t.Run("error byte", func(t *testing.T) {
		data := []byte{1} // error byte = 1 (failure)
		_, err := DeserializeRelinquishCertificateResult(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "relinquishCertificate failed with error byte 1")
	})
}
