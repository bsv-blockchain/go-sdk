package serializer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/util"
)

func TestSerializeCertificateNoSignature(t *testing.T) {
	t.Parallel()

	cert := xtValidCertificate(t)

	data, err := SerializeCertificateNoSignature(&cert)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// The no-signature form omits the trailing signature, so a round-trip
	// decode yields a certificate with a nil signature.
	got, err := DeserializeCertificate(data)
	require.NoError(t, err)
	assert.Nil(t, got.Signature)
}

func TestSerializeCertificateNoSignatureEmptyType(t *testing.T) {
	t.Parallel()

	cert := xtValidCertificate(t)
	cert.Type = [32]byte{}

	_, err := SerializeCertificateNoSignature(&cert)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cert type is empty")
}

func TestDeserializeCertificateInvalidCertifier(t *testing.T) {
	t.Parallel()

	w := util.NewWriter()
	w.WriteBytes(make([]byte, sizeType))     // type
	w.WriteBytes(make([]byte, sizeSerial))   // serial number
	w.WriteBytes(xtPub(t).Compressed())      // valid subject public key
	w.WriteByteValue(0x01)                   // invalid magic for certifier public key
	w.WriteBytes(make([]byte, sizePubKey-1)) // remaining certifier bytes

	_, err := DeserializeCertificate(w.Buf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error parsing certifier key")
}
