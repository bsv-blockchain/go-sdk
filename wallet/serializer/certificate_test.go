package serializer

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestCertificate(t *testing.T) {
	t.Run("serialize/deserialize", func(t *testing.T) {
		pk, err := ec.NewPrivateKey()
		require.NoError(t, err)
		cert := &wallet.Certificate{
			Type:               base64.StdEncoding.EncodeToString(padOrTrim([]byte("test-cert"), SizeType)),
			Subject:            pk.PubKey(),
			SerialNumber:       base64.StdEncoding.EncodeToString(make([]byte, SizeSerial)),
			Certifier:          pk.PubKey(),
			RevocationOutpoint: "0000000000000000000000000000000000000000000000000000000000000000.0",
			Signature:          hex.EncodeToString(make([]byte, 64)),
			Fields: map[string]string{
				"field1": "value1",
				"field2": "value2",
			},
		}

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
