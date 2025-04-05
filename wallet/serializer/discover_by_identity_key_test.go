package serializer

import (
	"encoding/base64"
	"encoding/hex"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDiscoverByIdentityKeyArgs(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.DiscoverByIdentityKeyArgs
	}{{
		name: "full args",
		args: &wallet.DiscoverByIdentityKeyArgs{
			IdentityKey:    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
			Limit:          10,
			Offset:         5,
			SeekPermission: boolPtr(true),
		},
	}, {
		name: "minimal args",
		args: &wallet.DiscoverByIdentityKeyArgs{
			IdentityKey: "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
		},
	}, {
		name: "undefined limit/offset",
		args: &wallet.DiscoverByIdentityKeyArgs{
			IdentityKey:    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
			SeekPermission: boolPtr(false),
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeDiscoverByIdentityKeyArgs(tt.args)
			require.NoError(t, err)

			// Test deserialization
			got, err := DeserializeDiscoverByIdentityKeyArgs(data)
			require.NoError(t, err)

			// Compare results
			require.Equal(t, tt.args, got)
		})
	}
}

func TestDiscoverCertificatesResult(t *testing.T) {
	t.Run("success with certificates", func(t *testing.T) {
		result := &wallet.DiscoverCertificatesResult{
			TotalCertificates: 2,
			Certificates: []wallet.IdentityCertificate{
				{
					Certificate: wallet.Certificate{
						Type:               base64.StdEncoding.EncodeToString(padOrTrim([]byte("dGVzdC10eXBl"), SizeType)),
						Subject:            hex.EncodeToString(make([]byte, 33)),
						SerialNumber:       base64.StdEncoding.EncodeToString(padOrTrim([]byte("c2VyaWFs"), SizeType)),
						Certifier:          hex.EncodeToString(make([]byte, 33)),
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
