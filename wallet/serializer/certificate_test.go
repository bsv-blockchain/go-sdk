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
		pk, err := ec.NewPrivateKey()
		require.NoError(t, err)
		cert := &wallet.Certificate{
			Subject:            pk.PubKey(),
			Certifier:          pk.PubKey(),
			RevocationOutpoint: tu.OutpointFromString(t, "a755810c21e17183ff6db6685f0de239fd3a0a3c0d4ba7773b0b0d1748541e2b.0"),
			Signature:          make([]byte, 64),
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

	t.Run("error byte", func(t *testing.T) {
		data := []byte{1} // error byte = 1 (failure)
		_, err := DeserializeCertificate(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "certificate deserialization failed with error byte 1")
	})
}
