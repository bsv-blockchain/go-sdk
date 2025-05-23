package serializer

import (
	"encoding/base64"
	"encoding/hex"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"testing"

	"github.com/bsv-blockchain/go-sdk/util"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestListCertificatesArgs(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.ListCertificatesArgs
	}{{
		name: "full args",
		args: &wallet.ListCertificatesArgs{
			Certifiers: []string{
				"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
				"02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
			},
			Types: []string{
				base64.StdEncoding.EncodeToString(tu.PadOrTrim([]byte("type1"), sizeType)),
				base64.StdEncoding.EncodeToString(tu.PadOrTrim([]byte("type2"), sizeType)),
			},
			Limit:            10,
			Offset:           5,
			Privileged:       util.BoolPtr(true),
			PrivilegedReason: "test-reason",
		},
	}, {
		name: "minimal args",
		args: &wallet.ListCertificatesArgs{
			Certifiers: []string{"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"},
			Types:      []string{base64.StdEncoding.EncodeToString(tu.PadOrTrim([]byte("minimal"), sizeType))},
		},
	}, {
		name: "empty certifiers and types",
		args: &wallet.ListCertificatesArgs{
			Certifiers: []string{},
			Types:      []string{},
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeListCertificatesArgs(tt.args)
			require.NoError(t, err)

			// Test deserialization
			got, err := DeserializeListCertificatesArgs(data)
			require.NoError(t, err)

			// Compare results
			require.Equal(t, tt.args, got)
		})
	}
}

func TestListCertificatesResult(t *testing.T) {
	t.Run("full result", func(t *testing.T) {
		pk, err := ec.NewPrivateKey()
		require.NoError(t, err)

		var typeCert1 [32]byte
		copy(typeCert1[:], []byte("cert1"))
		var typeCert2 [32]byte
		copy(typeCert2[:], []byte("cert2"))

		result := &wallet.ListCertificatesResult{
			TotalCertificates: 2,
			Certificates: []wallet.CertificateResult{
				{
					Certificate: wallet.Certificate{
						Type:               typeCert1,
						Subject:            pk.PubKey(),
						SerialNumber:       base64.StdEncoding.EncodeToString(tu.PadOrTrim([]byte("serial1"), sizeSerial)),
						Certifier:          pk.PubKey(),
						RevocationOutpoint: "0000000000000000000000000000000000000000000000000000000000000000.0",
						Signature:          hex.EncodeToString(make([]byte, 64)),
						Fields: map[string]string{
							"field1": "value1",
						},
					},
					Keyring: map[string]string{
						"key1": "value1",
					},
					Verifier: "verifier1",
				},
				{
					Certificate: wallet.Certificate{
						Type:               typeCert2,
						Subject:            pk.PubKey(),
						SerialNumber:       base64.StdEncoding.EncodeToString(tu.PadOrTrim([]byte("serial2"), sizeSerial)),
						Certifier:          pk.PubKey(),
						RevocationOutpoint: "0000000000000000000000000000000000000000000000000000000000000000.0",
					},
				},
			},
		}

		data, err := SerializeListCertificatesResult(result)
		require.NoError(t, err)

		got, err := DeserializeListCertificatesResult(data)
		require.NoError(t, err)
		require.Equal(t, result, got)
	})

	t.Run("error byte", func(t *testing.T) {
		data := []byte{1} // error byte = 1 (failure)
		_, err := DeserializeListCertificatesResult(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "listCertificates failed with error byte 1")
	})
}
