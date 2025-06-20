package serializer

import (
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestCertificate(t *testing.T) {
	t.Run("serialize/deserialize", func(t *testing.T) {
		sig := tu.GetSigFromHex(t, "3045022100a6f09ee70382ab364f3f6b040aebb8fe7a51dbc3b4c99cfeb2f7756432162833022067349b91a6319345996faddf36d1b2f3a502e4ae002205f9d2db85474f9aed5a")
		pk, err := ec.NewPrivateKey()
		require.NoError(t, err)
		cert := &wallet.Certificate{
			Subject:            pk.PubKey(),
			Certifier:          pk.PubKey(),
			RevocationOutpoint: tu.OutpointFromString(t, "a755810c21e17183ff6db6685f0de239fd3a0a3c0d4ba7773b0b0d1748541e2b.0"),
			Signature:          sig,
			Fields: map[string]string{
				"field1": "value1",
				"field2": "value2",
			},
		}
		copy(cert.Type[:], []byte("test-cert"))

		data, err := SerializeCertificate(cert)
		require.NoError(t, err)

		got, err := DeserializeCertificate(data)
		require.NoError(t, err)
		require.Equal(t, cert, got)
	})
}
