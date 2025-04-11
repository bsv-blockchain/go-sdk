package certificates

import (
	"encoding/base64"
	"testing"

	"github.com/bsv-blockchain/go-sdk/overlay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificate(t *testing.T) {
	// Sample data for testing - use consistent data like in TS
	sampleType := wallet.Base64String(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	sampleSerialNumber := wallet.Base64String(base64.StdEncoding.EncodeToString(make([]byte, 32)))

	// Create private keys
	sampleSubjectPrivateKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	sampleSubjectPubKey := sampleSubjectPrivateKey.PubKey()

	sampleCertifierPrivateKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	sampleCertifierPubKey := sampleCertifierPrivateKey.PubKey()

	// Create a revocation outpoint
	txid := make([]byte, 32)
	var outpoint overlay.Outpoint
	copy(outpoint.Txid[:], txid)
	outpoint.OutputIndex = 1
	sampleRevocationOutpoint := &outpoint

	// Convert string maps to the proper types
	sampleFields := map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{
		wallet.CertificateFieldNameUnder50Bytes("name"):         wallet.Base64String("Alice"),
		wallet.CertificateFieldNameUnder50Bytes("email"):        wallet.Base64String("alice@example.com"),
		wallet.CertificateFieldNameUnder50Bytes("organization"): wallet.Base64String("Example Corp"),
	}
	sampleFieldsEmpty := map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{}

	// Helper function to create a ProtoWallet for testing
	createProtoWallet := func(privateKey *ec.PrivateKey) *wallet.ProtoWallet {
		protoWallet, err := wallet.NewProtoWallet(privateKey)
		require.NoError(t, err)
		return protoWallet
	}

	t.Run("should construct a Certificate with valid data", func(t *testing.T) {
		certificate := &Certificate{
			Type:               sampleType,
			SerialNumber:       sampleSerialNumber,
			Subject:            *sampleSubjectPubKey,
			Certifier:          *sampleCertifierPubKey,
			RevocationOutpoint: sampleRevocationOutpoint,
			Fields:             sampleFields,
			Signature:          nil, // No signature
		}

		assert.Equal(t, sampleType, certificate.Type)
		assert.Equal(t, sampleSerialNumber, certificate.SerialNumber)
		assert.True(t, certificate.Subject.IsEqual(sampleSubjectPubKey))
		assert.True(t, certificate.Certifier.IsEqual(sampleCertifierPubKey))
		assert.Equal(t, sampleRevocationOutpoint, certificate.RevocationOutpoint)
		assert.Nil(t, certificate.Signature)
		assert.Equal(t, sampleFields, certificate.Fields)
	})

	t.Run("should serialize and deserialize the Certificate without signature", func(t *testing.T) {
		certificate := &Certificate{
			Type:               sampleType,
			SerialNumber:       sampleSerialNumber,
			Subject:            *sampleSubjectPubKey,
			Certifier:          *sampleCertifierPubKey,
			RevocationOutpoint: sampleRevocationOutpoint,
			Fields:             sampleFields,
			Signature:          nil, // No signature
		}

		serialized, err := certificate.ToBinary(false) // Exclude signature
		require.NoError(t, err)

		deserializedCertificate, err := CertificateFromBinary(serialized)
		require.NoError(t, err)

		assert.Equal(t, sampleType, deserializedCertificate.Type)
		assert.Equal(t, sampleSerialNumber, deserializedCertificate.SerialNumber)
		assert.True(t, deserializedCertificate.Subject.IsEqual(&certificate.Subject))
		assert.True(t, deserializedCertificate.Certifier.IsEqual(&certificate.Certifier))
		assert.Equal(t, certificate.RevocationOutpoint, deserializedCertificate.RevocationOutpoint)
		assert.Nil(t, deserializedCertificate.Signature)
		assert.Equal(t, sampleFields, deserializedCertificate.Fields)
	})

	t.Run("should serialize and deserialize the Certificate with signature", func(t *testing.T) {
		certificate := &Certificate{
			Type:               sampleType,
			SerialNumber:       sampleSerialNumber,
			Subject:            *sampleSubjectPubKey,
			Certifier:          *sampleCertifierPubKey,
			RevocationOutpoint: sampleRevocationOutpoint,
			Fields:             sampleFields,
			Signature:          nil, // No signature
		}

		// Create a ProtoWallet for signing
		certifierProtoWallet := createProtoWallet(sampleCertifierPrivateKey)

		err = certificate.Sign(certifierProtoWallet)
		require.NoError(t, err)

		serialized, err := certificate.ToBinary(true) // Include signature
		require.NoError(t, err)

		deserializedCertificate, err := CertificateFromBinary(serialized)
		require.NoError(t, err)

		assert.Equal(t, sampleType, deserializedCertificate.Type)
		assert.Equal(t, sampleSerialNumber, deserializedCertificate.SerialNumber)
		assert.True(t, deserializedCertificate.Subject.IsEqual(&certificate.Subject))
		assert.True(t, deserializedCertificate.Certifier.IsEqual(&certificate.Certifier))
		assert.Equal(t, certificate.RevocationOutpoint, deserializedCertificate.RevocationOutpoint)
		assert.NotNil(t, deserializedCertificate.Signature)
		assert.Equal(t, certificate.Signature, deserializedCertificate.Signature)
		assert.Equal(t, sampleFields, deserializedCertificate.Fields)
	})

	t.Run("should sign the Certificate and verify the signature successfully", func(t *testing.T) {
		certificate := &Certificate{
			Type:               sampleType,
			SerialNumber:       sampleSerialNumber,
			Subject:            *sampleSubjectPubKey,
			Certifier:          *sampleCertifierPubKey,
			RevocationOutpoint: sampleRevocationOutpoint,
			Fields:             sampleFields,
			Signature:          nil, // No signature
		}

		// Create a ProtoWallet for signing
		certifierProtoWallet := createProtoWallet(sampleCertifierPrivateKey)

		err = certificate.Sign(certifierProtoWallet)
		require.NoError(t, err)

		// Verify the signature
		err = certificate.Verify()
		assert.NoError(t, err)
	})

	t.Run("should fail verification if the Certificate is tampered with", func(t *testing.T) {
		certificate := &Certificate{
			Type:               sampleType,
			SerialNumber:       sampleSerialNumber,
			Subject:            *sampleSubjectPubKey,
			Certifier:          *sampleCertifierPubKey,
			RevocationOutpoint: sampleRevocationOutpoint,
			Fields:             sampleFields,
			Signature:          nil, // No signature
		}

		// Create a ProtoWallet for signing
		certifierProtoWallet := createProtoWallet(sampleCertifierPrivateKey)

		err = certificate.Sign(certifierProtoWallet)
		require.NoError(t, err)

		// Tamper with the certificate (modify a field)
		certificate.Fields[wallet.CertificateFieldNameUnder50Bytes("email")] = wallet.Base64String("attacker@example.com")

		// Verify the signature
		err = certificate.Verify()
		assert.Error(t, err)
	})

	t.Run("should fail verification if the signature is missing", func(t *testing.T) {
		certificate := &Certificate{
			Type:               sampleType,
			SerialNumber:       sampleSerialNumber,
			Subject:            *sampleSubjectPubKey,
			Certifier:          *sampleCertifierPubKey,
			RevocationOutpoint: sampleRevocationOutpoint,
			Fields:             sampleFields,
			Signature:          nil, // No signature
		}

		// Verify the signature
		err = certificate.Verify()
		assert.Error(t, err)
	})

	t.Run("should fail verification if the signature is incorrect", func(t *testing.T) {
		// Create an incorrect signature
		incorrectSignature := []byte("3045022100cde229279465bb91992ccbc30bf6ed4eb8cdd9d517f31b30ff778d500d5400010220134f0e4065984f8668a642a5ad7a80886265f6aaa56d215d6400c216a4802177")

		certificate := &Certificate{
			Type:               sampleType,
			SerialNumber:       sampleSerialNumber,
			Subject:            *sampleSubjectPubKey,
			Certifier:          *sampleCertifierPubKey,
			RevocationOutpoint: sampleRevocationOutpoint,
			Fields:             sampleFields,
			Signature:          incorrectSignature,
		}

		// Verify the signature
		err = certificate.Verify()
		assert.Error(t, err)
	})

	t.Run("should handle certificates with empty fields", func(t *testing.T) {
		certificate := &Certificate{
			Type:               sampleType,
			SerialNumber:       sampleSerialNumber,
			Subject:            *sampleSubjectPubKey,
			Certifier:          *sampleCertifierPubKey,
			RevocationOutpoint: sampleRevocationOutpoint,
			Fields:             sampleFieldsEmpty, // Using empty fields
			Signature:          nil,               // No signature
		}

		// Create a ProtoWallet for signing
		certifierProtoWallet := createProtoWallet(sampleCertifierPrivateKey)

		err = certificate.Sign(certifierProtoWallet)
		require.NoError(t, err)

		// Serialize and deserialize
		serialized, err := certificate.ToBinary(true)
		require.NoError(t, err)

		deserializedCertificate, err := CertificateFromBinary(serialized)
		require.NoError(t, err)

		assert.Equal(t, sampleFieldsEmpty, deserializedCertificate.Fields)

		// Verify the signature
		err = deserializedCertificate.Verify()
		assert.NoError(t, err)
	})

	t.Run("should correctly handle serialization/deserialization when signature is excluded", func(t *testing.T) {
		// Create a dummy signature
		dummySignature := []byte("deadbeef1234")

		certificate := &Certificate{
			Type:               sampleType,
			SerialNumber:       sampleSerialNumber,
			Subject:            *sampleSubjectPubKey,
			Certifier:          *sampleCertifierPubKey,
			RevocationOutpoint: sampleRevocationOutpoint,
			Fields:             sampleFields,
			Signature:          dummySignature,
		}

		// Serialize without signature
		serialized, err := certificate.ToBinary(false)
		require.NoError(t, err)

		deserializedCertificate, err := CertificateFromBinary(serialized)
		require.NoError(t, err)

		assert.Nil(t, deserializedCertificate.Signature)
		assert.Equal(t, sampleFields, deserializedCertificate.Fields)
	})

	t.Run("should correctly handle certificates with long field names and values", func(t *testing.T) {
		longFieldName := ""
		for i := 0; i < 10; i++ {
			longFieldName += "longFieldName_"
		}

		longFieldValue := ""
		for i := 0; i < 20; i++ {
			longFieldValue += "longFieldValue_"
		}

		fields := map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{
			wallet.CertificateFieldNameUnder50Bytes(longFieldName): wallet.Base64String(longFieldValue),
		}

		certificate := &Certificate{
			Type:               sampleType,
			SerialNumber:       sampleSerialNumber,
			Subject:            *sampleSubjectPubKey,
			Certifier:          *sampleCertifierPubKey,
			RevocationOutpoint: sampleRevocationOutpoint,
			Fields:             fields,
			Signature:          nil, // No signature
		}

		// Create a ProtoWallet for signing
		certifierProtoWallet := createProtoWallet(sampleCertifierPrivateKey)

		err = certificate.Sign(certifierProtoWallet)
		require.NoError(t, err)

		// Serialize and deserialize
		serialized, err := certificate.ToBinary(true)
		require.NoError(t, err)

		deserializedCertificate, err := CertificateFromBinary(serialized)
		require.NoError(t, err)

		assert.Equal(t, fields, deserializedCertificate.Fields)

		// Verify the signature
		err = deserializedCertificate.Verify()
		assert.NoError(t, err)
	})

	t.Run("should correctly serialize and deserialize the revocationOutpoint", func(t *testing.T) {
		certificate := &Certificate{
			Type:               sampleType,
			SerialNumber:       sampleSerialNumber,
			Subject:            *sampleSubjectPubKey,
			Certifier:          *sampleCertifierPubKey,
			RevocationOutpoint: sampleRevocationOutpoint,
			Fields:             sampleFields,
			Signature:          nil, // No signature
		}

		serialized, err := certificate.ToBinary(false)
		require.NoError(t, err)

		deserializedCertificate, err := CertificateFromBinary(serialized)
		require.NoError(t, err)

		assert.Equal(t, certificate.RevocationOutpoint, deserializedCertificate.RevocationOutpoint)
	})

	t.Run("should throw if already signed, and should update the certifier field if it differs", func(t *testing.T) {
		// Scenario 1: Certificate already has a signature
		preSignedCertificate := &Certificate{
			Type:               sampleType,
			SerialNumber:       sampleSerialNumber,
			Subject:            *sampleSubjectPubKey,
			Certifier:          *sampleCertifierPubKey,
			RevocationOutpoint: sampleRevocationOutpoint,
			Fields:             sampleFields,
			Signature:          []byte("deadbeef"), // Already has a placeholder signature
		}

		certifierProtoWallet := createProtoWallet(sampleCertifierPrivateKey)

		// Trying to sign again should error
		err = preSignedCertificate.Sign(certifierProtoWallet)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "certificate has already been signed")

		// Scenario 2: The certifier property is set to something different from the wallet's public key
		mismatchedCertifierPrivateKey, err := ec.NewPrivateKey()
		require.NoError(t, err)
		mismatchedCertifierPubKey := mismatchedCertifierPrivateKey.PubKey()

		certificateWithMismatch := &Certificate{
			Type:               sampleType,
			SerialNumber:       sampleSerialNumber,
			Subject:            *sampleSubjectPubKey,
			Certifier:          *mismatchedCertifierPubKey, // Different from actual wallet key
			RevocationOutpoint: sampleRevocationOutpoint,
			Fields:             sampleFields,
			Signature:          nil,
		}

		// Sign the certificate; it should automatically update
		// the certifier field to match the wallet's actual public key
		err = certificateWithMismatch.Sign(certifierProtoWallet)
		require.NoError(t, err)

		// Get the expected public key from the wallet
		pubKey, err := certifierProtoWallet.GetPublicKey(&wallet.GetPublicKeyArgs{
			IdentityKey: true,
		})
		require.NoError(t, err)

		assert.True(t, certificateWithMismatch.Certifier.IsEqual(pubKey))
		err = certificateWithMismatch.Verify()
		assert.NoError(t, err)
	})
}
