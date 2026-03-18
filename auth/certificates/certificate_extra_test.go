package certificates

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

// Helper that builds a valid signed certificate for testing
func buildSignedCert(t *testing.T) *Certificate {
	t.Helper()

	typeBytes := bytes.Repeat([]byte{3}, 32)
	sampleType := wallet.StringBase64(base64.StdEncoding.EncodeToString(typeBytes))
	serialBytes := bytes.Repeat([]byte{4}, 32)
	sampleSerial := wallet.StringBase64(base64.StdEncoding.EncodeToString(serialBytes))

	subjectKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	certifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	var outpoint transaction.Outpoint
	outpoint.Index = 0

	cert := &Certificate{
		Type:               sampleType,
		SerialNumber:       sampleSerial,
		Subject:            *subjectKey.PubKey(),
		Certifier:          *certifierKey.PubKey(),
		RevocationOutpoint: &outpoint,
		Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{
			"name": "Alice",
		},
	}

	certifierWallet, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{
		Type:       wallet.ProtoWalletArgsTypePrivateKey,
		PrivateKey: certifierKey,
	})
	require.NoError(t, err)

	err = cert.Sign(context.Background(), certifierWallet)
	require.NoError(t, err)

	return cert
}

func TestCertificate_NewCertificate(t *testing.T) {
	typeBytes := bytes.Repeat([]byte{1}, 32)
	sampleType := wallet.StringBase64(base64.StdEncoding.EncodeToString(typeBytes))
	serialBytes := bytes.Repeat([]byte{2}, 32)
	sampleSerial := wallet.StringBase64(base64.StdEncoding.EncodeToString(serialBytes))

	subjectKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	certifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	var outpoint transaction.Outpoint
	outpoint.Index = 1

	fields := map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{
		"name": "Alice",
	}

	sig := []byte{0x30, 0x45}

	cert := NewCertificate(sampleType, sampleSerial, *subjectKey.PubKey(), *certifierKey.PubKey(), &outpoint, fields, sig)
	require.NotNil(t, cert)
	require.Equal(t, sampleType, cert.Type)
	require.Equal(t, sampleSerial, cert.SerialNumber)
	require.True(t, cert.Subject.IsEqual(subjectKey.PubKey()))
	require.True(t, cert.Certifier.IsEqual(certifierKey.PubKey()))
	require.Equal(t, &outpoint, cert.RevocationOutpoint)
	require.Equal(t, fields, cert.Fields)
	require.Equal(t, sig, []byte(cert.Signature))
}

func TestCertificate_MarshalUnmarshalJSON(t *testing.T) {
	t.Run("marshal and unmarshal round-trip", func(t *testing.T) {
		cert := buildSignedCert(t)

		data, err := json.Marshal(cert)
		require.NoError(t, err)
		require.NotEmpty(t, data)

		var restored Certificate
		err = json.Unmarshal(data, &restored)
		require.NoError(t, err)

		require.Equal(t, cert.Type, restored.Type)
		require.Equal(t, cert.SerialNumber, restored.SerialNumber)
		require.True(t, cert.Subject.IsEqual(&restored.Subject))
	})

	t.Run("SignatureHex marshal empty bytes", func(t *testing.T) {
		var s SignatureHex
		data, err := s.MarshalJSON()
		require.NoError(t, err)
		require.Equal(t, []byte(""), data)
	})

	t.Run("SignatureHex unmarshal valid hex string", func(t *testing.T) {
		var s SignatureHex
		err := s.UnmarshalJSON([]byte(`"deadbeef"`))
		require.NoError(t, err)
		require.Equal(t, SignatureHex([]byte{0xde, 0xad, 0xbe, 0xef}), s)
	})

	t.Run("SignatureHex unmarshal empty bytes", func(t *testing.T) {
		var s SignatureHex
		err := s.UnmarshalJSON([]byte{})
		require.NoError(t, err)
		require.Nil(t, []byte(s))
	})

	t.Run("SignatureHex unmarshal non-string JSON", func(t *testing.T) {
		var s SignatureHex
		err := s.UnmarshalJSON([]byte(`123`))
		require.Error(t, err)
	})

	t.Run("SignatureHex unmarshal odd-length hex", func(t *testing.T) {
		var s SignatureHex
		err := s.UnmarshalJSON([]byte(`"abc"`))
		require.Error(t, err)
	})

	t.Run("SignatureHex unmarshal invalid hex", func(t *testing.T) {
		var s SignatureHex
		err := s.UnmarshalJSON([]byte(`"zzzz"`))
		require.Error(t, err)
	})

	t.Run("SignatureHex unmarshal too short", func(t *testing.T) {
		var s SignatureHex
		err := s.UnmarshalJSON([]byte(`"`))
		require.Error(t, err)
	})
}

func TestCertificate_Verify_Errors(t *testing.T) {
	t.Run("verify fails when no signature", func(t *testing.T) {
		typeBytes := bytes.Repeat([]byte{1}, 32)
		sampleType := wallet.StringBase64(base64.StdEncoding.EncodeToString(typeBytes))
		serialBytes := bytes.Repeat([]byte{2}, 32)
		sampleSerial := wallet.StringBase64(base64.StdEncoding.EncodeToString(serialBytes))

		subjectKey, err := ec.NewPrivateKey()
		require.NoError(t, err)
		certifierKey, err := ec.NewPrivateKey()
		require.NoError(t, err)

		cert := &Certificate{
			Type:         sampleType,
			SerialNumber: sampleSerial,
			Subject:      *subjectKey.PubKey(),
			Certifier:    *certifierKey.PubKey(),
			Fields:       map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{},
		}

		err = cert.Verify(context.Background())
		require.ErrorIs(t, err, ErrNotSigned)
	})

	t.Run("verify fails with invalid DER signature", func(t *testing.T) {
		typeBytes := bytes.Repeat([]byte{1}, 32)
		sampleType := wallet.StringBase64(base64.StdEncoding.EncodeToString(typeBytes))
		serialBytes := bytes.Repeat([]byte{2}, 32)
		sampleSerial := wallet.StringBase64(base64.StdEncoding.EncodeToString(serialBytes))

		subjectKey, err := ec.NewPrivateKey()
		require.NoError(t, err)
		certifierKey, err := ec.NewPrivateKey()
		require.NoError(t, err)

		var outpoint transaction.Outpoint

		cert := &Certificate{
			Type:               sampleType,
			SerialNumber:       sampleSerial,
			Subject:            *subjectKey.PubKey(),
			Certifier:          *certifierKey.PubKey(),
			RevocationOutpoint: &outpoint,
			Fields:             map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{},
			Signature:          []byte{0x00, 0x01, 0x02}, // invalid DER
		}

		err = cert.Verify(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse signature")
	})
}

func TestCertificate_Sign_AlreadySigned(t *testing.T) {
	t.Run("sign fails if already signed", func(t *testing.T) {
		cert := buildSignedCert(t)
		require.NotNil(t, cert.Signature)

		// Try to sign again
		certifierKey, err := ec.NewPrivateKey()
		require.NoError(t, err)
		certifierWallet, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{
			Type:       wallet.ProtoWalletArgsTypePrivateKey,
			PrivateKey: certifierKey,
		})
		require.NoError(t, err)

		err = cert.Sign(context.Background(), certifierWallet)
		require.ErrorIs(t, err, ErrAlreadySigned)
	})
}

func TestCertificate_ToBinary_WithSignature(t *testing.T) {
	t.Run("ToBinary includes signature when requested", func(t *testing.T) {
		cert := buildSignedCert(t)

		withSig, err := cert.ToBinary(true)
		require.NoError(t, err)

		withoutSig, err := cert.ToBinary(false)
		require.NoError(t, err)

		// With signature should be longer
		require.Greater(t, len(withSig), len(withoutSig))
	})
}

func TestCertificateFromBinary_RoundTrip(t *testing.T) {
	t.Run("serialization round-trip with signature", func(t *testing.T) {
		cert := buildSignedCert(t)

		data, err := cert.ToBinary(true)
		require.NoError(t, err)

		restored, err := CertificateFromBinary(data)
		require.NoError(t, err)
		require.Equal(t, cert.Type, restored.Type)
		require.Equal(t, cert.SerialNumber, restored.SerialNumber)
		require.True(t, cert.Subject.IsEqual(&restored.Subject))
		require.True(t, cert.Certifier.IsEqual(&restored.Certifier))
	})

	t.Run("CertificateFromBinary fails with invalid data", func(t *testing.T) {
		_, err := CertificateFromBinary([]byte{0x00, 0x01, 0x02})
		require.Error(t, err)
	})
}

func TestNewVerifiableCertificateFromBinary(t *testing.T) {
	t.Run("creates verifiable certificate from binary", func(t *testing.T) {
		cert := buildSignedCert(t)

		data, err := cert.ToBinary(true)
		require.NoError(t, err)

		vc, err := NewVerifiableCertificateFromBinary(data)
		require.NoError(t, err)
		require.NotNil(t, vc)
		require.Equal(t, cert.Type, vc.Type)
		require.NotNil(t, vc.Keyring)
		require.NotNil(t, vc.DecryptedFields)
	})

	t.Run("fails with invalid data", func(t *testing.T) {
		_, err := NewVerifiableCertificateFromBinary([]byte{0xFF})
		require.Error(t, err)
	})
}

func TestGetCertificateEncryptionDetails(t *testing.T) {
	t.Run("with serial number", func(t *testing.T) {
		proto, keyID := GetCertificateEncryptionDetails("fieldName", "serialNum")
		require.Equal(t, "certificate field encryption", proto.Protocol)
		require.Equal(t, "serialNum fieldName", keyID)
	})

	t.Run("without serial number", func(t *testing.T) {
		proto, keyID := GetCertificateEncryptionDetails("fieldName", "")
		require.Equal(t, "certificate field encryption", proto.Protocol)
		require.Equal(t, "fieldName", keyID)
	})
}
