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

	t.Run("error byte", func(t *testing.T) {
		data := []byte{1} // error byte = 1 (failure)
		_, err := DeserializeRelinquishCertificateResult(data)
		require.Error(t, err, "deserializing with error byte should produce an error")
		require.Contains(t, err.Error(), "relinquishCertificate failed with error byte 1", "error message should indicate failure and error byte")
	})
}
