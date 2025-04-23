package serializer

import (
	"encoding/base64"
	"encoding/hex"
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
		require.NoError(t, err)
		result := &wallet.DiscoverCertificatesResult{
			TotalCertificates: 2,
			Certificates: []wallet.IdentityCertificate{
				{
					Certificate: wallet.Certificate{
						Type:               base64.StdEncoding.EncodeToString(padOrTrim([]byte("dGVzdC10eXBl"), SizeType)),
						Subject:            pk.PubKey(),
						SerialNumber:       base64.StdEncoding.EncodeToString(padOrTrim([]byte("c2VyaWFs"), SizeType)),
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
		require.NoError(t, err)

		got, err := DeserializeDiscoverCertificatesResult(data)
		require.NoError(t, err)
		require.Equal(t, result, got)
	})

	t.Run("error byte", func(t *testing.T) {
		data := []byte{1} // error byte = 1 (failure)
		_, err := DeserializeDiscoverCertificatesResult(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "discoverByIdentityKey failed with error byte 1")
	})
}
