package serializer

import (
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
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
			Certifiers: []*ec.PublicKey{
				tu.GetPKFromHex(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
				tu.GetPKFromHex(t, "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
			},
			Types: []wallet.CertificateType{
				tu.GetByte32FromString("type1"),
				tu.GetByte32FromString("type2"),
			},
			Limit:            10,
			Offset:           5,
			Privileged:       util.BoolPtr(true),
			PrivilegedReason: "test-reason",
		},
	}, {
		name: "minimal args",
		args: &wallet.ListCertificatesArgs{
			Certifiers: []*ec.PublicKey{tu.GetPKFromHex(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")},
			Types:      []wallet.CertificateType{tu.GetByte32FromString("minimal")},
		},
	}, {
		name: "empty certifiers and types",
		args: &wallet.ListCertificatesArgs{
			Certifiers: []*ec.PublicKey{},
			Types:      []wallet.CertificateType{},
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

		result := &wallet.ListCertificatesResult{
			TotalCertificates: 2,
			Certificates: []wallet.CertificateResult{
				{
					Certificate: wallet.Certificate{
						Type:               tu.GetByte32FromString("cert1"),
						Subject:            pk.PubKey(),
						SerialNumber:       tu.GetByte32FromString("serial1"),
						Certifier:          pk.PubKey(),
						RevocationOutpoint: tu.OutpointFromString(t, "a755810c21e17183ff6db6685f0de239fd3a0a3c0d4ba7773b0b0d1748541e2b.0"),
						Signature:          make([]byte, 64),
						Fields: map[string]string{
							"field1": "value1",
						},
					},
					Keyring: map[string]string{
						"key1": "value1",
					},
					Verifier: []byte("verifier1"),
				},
				{
					Certificate: wallet.Certificate{
						Type:               tu.GetByte32FromString("cert2"),
						Subject:            pk.PubKey(),
						SerialNumber:       tu.GetByte32FromString("serial2"),
						Certifier:          pk.PubKey(),
						RevocationOutpoint: tu.OutpointFromString(t, "a755810c21e17183ff6db6685f0de239fd3a0a3c0d4ba7773b0b0d1748541e2b.0"),
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
