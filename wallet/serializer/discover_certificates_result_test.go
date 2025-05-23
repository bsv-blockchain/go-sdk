package serializer

import (
	"encoding/hex"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestDiscoverCertificatesResult(t *testing.T) {
	// Reuse the same test from discover_by_identity_key_test.go
	// since the result format is identical
	t.Run("success with certificates", func(t *testing.T) {
		pk, err := ec.NewPrivateKey()
		require.NoError(t, err, "generating private key should not error")
		var certType [32]byte
		copy(certType[:], "dGVzdC10eXBl") // "test-type" in base64
		result := &wallet.DiscoverCertificatesResult{
			TotalCertificates: 2,
			Certificates: []wallet.IdentityCertificate{
				{
					Certificate: wallet.Certificate{
						Type:               certType,
						Subject:            pk.PubKey(),
						SerialNumber:       tu.GetByte32FromString("c2VyaWFs"),
						Certifier:          pk.PubKey(),
						RevocationOutpoint: "0000000000000000000000000000000000000000000000000000000000000000.0",
						Signature:          hex.EncodeToString(make([]byte, 64)),
						Fields: map[string]string{
							"field1": "value1",
						},
					},
					CertifierInfo: wallet.IdentityCertifier{
						Name:        "Test Certifier",
						IconUrl:     "https://example.com/icon.png",
						Description: "Test description",
						Trust:       5,
					},
					PubliclyRevealedKeyring: map[string]string{
						"key1": "value1",
					},
					DecryptedFields: map[string]string{
						"field1": "decrypted1",
					},
				},
			},
		}

		data, err := SerializeDiscoverCertificatesResult(result)
		require.NoError(t, err, "serializing DiscoverCertificatesResult should not error")

		got, err := DeserializeDiscoverCertificatesResult(data)
		require.NoError(t, err, "deserializing DiscoverCertificatesResult should not error")
		require.Equal(t, result, got, "deserialized result should match original result")
	})

	t.Run("error byte", func(t *testing.T) {
		data := []byte{1} // error byte = 1 (failure)
		_, err := DeserializeDiscoverCertificatesResult(data)
		require.Error(t, err, "deserializing with error byte should produce an error")
		require.Contains(t, err.Error(), "discoverByIdentityKey failed with error byte 1", "error message should indicate failure and error byte")
	})
}
