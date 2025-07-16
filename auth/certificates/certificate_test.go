package certificates

import (
	"encoding/base64"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificate(t *testing.T) {
	// Sample data for testing - use consistent data like in TS
	typeBytes := tu.GetByte32FromString("test-certificate-type")
	sampleType := wallet.StringBase64(base64.StdEncoding.EncodeToString(typeBytes[:]))

	serialBytes := tu.GetByte32FromString("test-serial-number")
	sampleSerialNumber := wallet.StringBase64(base64.StdEncoding.EncodeToString(serialBytes[:]))

	// Create private keys
	sampleSubjectPrivateKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	sampleSubjectPubKey := sampleSubjectPrivateKey.PubKey()

	sampleCertifierPrivateKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	sampleCertifierPubKey := sampleCertifierPrivateKey.PubKey()

	// Create a revocation outpoint
	txid := make([]byte, 32)
	var outpoint transaction.Outpoint
	copy(outpoint.Txid[:], txid)
	outpoint.Index = 1
	sampleRevocationOutpoint := &outpoint

	// Convert string maps to the proper types
	sampleFields := map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{
		wallet.CertificateFieldNameUnder50Bytes("name"):         wallet.StringBase64("Alice"),
		wallet.CertificateFieldNameUnder50Bytes("email"):        wallet.StringBase64("alice@example.com"),
		wallet.CertificateFieldNameUnder50Bytes("organization"): wallet.StringBase64("Example Corp"),
	}
	sampleFieldsEmpty := map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{}

	// Helper function to create a ProtoWallet for testing
	createProtoWallet := func(privateKey *ec.PrivateKey) *wallet.ProtoWallet {
		protoWallet, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{Type: wallet.ProtoWalletArgsTypePrivateKey, PrivateKey: privateKey})
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

		err = certificate.Sign(t.Context(), certifierProtoWallet)
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

		err = certificate.Sign(t.Context(), certifierProtoWallet)
		require.NoError(t, err)

		// Verify the signature
		err = certificate.Verify(t.Context())
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

		err = certificate.Sign(t.Context(), certifierProtoWallet)
		require.NoError(t, err)

		// Tamper with the certificate (modify a field)
		certificate.Fields[wallet.CertificateFieldNameUnder50Bytes("email")] = wallet.StringBase64("attacker@example.com")

		// Verify the signature
		err = certificate.Verify(t.Context())
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
		err = certificate.Verify(t.Context())
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
		err = certificate.Verify(t.Context())
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

		err = certificate.Sign(t.Context(), certifierProtoWallet)
		require.NoError(t, err)

		// Serialize and deserialize
		serialized, err := certificate.ToBinary(true)
		require.NoError(t, err)

		deserializedCertificate, err := CertificateFromBinary(serialized)
		require.NoError(t, err)

		assert.Equal(t, sampleFieldsEmpty, deserializedCertificate.Fields)

		// Verify the signature
		err = deserializedCertificate.Verify(t.Context())
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

		fields := map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{
			wallet.CertificateFieldNameUnder50Bytes(longFieldName): wallet.StringBase64(longFieldValue),
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

		err = certificate.Sign(t.Context(), certifierProtoWallet)
		require.NoError(t, err)

		// Serialize and deserialize
		serialized, err := certificate.ToBinary(true)
		require.NoError(t, err)

		deserializedCertificate, err := CertificateFromBinary(serialized)
		require.NoError(t, err)

		assert.Equal(t, fields, deserializedCertificate.Fields)

		// Verify the signature
		err = deserializedCertificate.Verify(t.Context())
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
		err = preSignedCertificate.Sign(t.Context(), certifierProtoWallet)
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
		err = certificateWithMismatch.Sign(t.Context(), certifierProtoWallet)
		require.NoError(t, err)

		// Get the expected public key from the wallet
		pubKey, err := certifierProtoWallet.GetPublicKey(t.Context(), wallet.GetPublicKeyArgs{
			IdentityKey: true,
		}, "")
		require.NoError(t, err)

		assert.True(t, certificateWithMismatch.Certifier.IsEqual(pubKey.PublicKey))
		err = certificateWithMismatch.Verify(t.Context())
		assert.NoError(t, err)
	})

	t.Run("ToWalletCertificate should convert Certificate to wallet.Certificate correctly", func(t *testing.T) {
		certificate := &Certificate{
			Type:               sampleType,
			SerialNumber:       sampleSerialNumber,
			Subject:            *sampleSubjectPubKey,
			Certifier:          *sampleCertifierPubKey,
			RevocationOutpoint: sampleRevocationOutpoint,
			Fields:             sampleFields,
			Signature:          nil,
		}

		walletCert, err := certificate.ToWalletCertificate()
		require.NoError(t, err)

		// Verify the conversion
		assert.NotNil(t, walletCert)
		assert.Equal(t, &certificate.Subject, walletCert.Subject)
		assert.Equal(t, &certificate.Certifier, walletCert.Certifier)
		assert.Nil(t, walletCert.Signature)

		// Convert type and serial back to verify
		convertedType := wallet.StringBase64FromArray(walletCert.Type)
		convertedSerial := wallet.StringBase64FromArray(walletCert.SerialNumber)
		assert.Equal(t, sampleType, convertedType)
		assert.Equal(t, sampleSerialNumber, convertedSerial)

		// Check fields conversion
		assert.Equal(t, len(sampleFields), len(walletCert.Fields))
		for fieldName, fieldValue := range sampleFields {
			assert.Equal(t, string(fieldValue), walletCert.Fields[string(fieldName)])
		}

		// Check revocation outpoint conversion
		assert.NotNil(t, walletCert.RevocationOutpoint)
		assert.Equal(t, certificate.RevocationOutpoint.Txid, walletCert.RevocationOutpoint.Txid)
		assert.Equal(t, certificate.RevocationOutpoint.Index, walletCert.RevocationOutpoint.Index)
	})

	t.Run("ToWalletCertificate should handle certificate with signature", func(t *testing.T) {
		certificate := &Certificate{
			Type:               sampleType,
			SerialNumber:       sampleSerialNumber,
			Subject:            *sampleSubjectPubKey,
			Certifier:          *sampleCertifierPubKey,
			RevocationOutpoint: sampleRevocationOutpoint,
			Fields:             sampleFields,
			Signature:          nil,
		}

		// Sign the certificate first
		certifierProtoWallet := createProtoWallet(sampleCertifierPrivateKey)
		err = certificate.Sign(t.Context(), certifierProtoWallet)
		require.NoError(t, err)

		walletCert, err := certificate.ToWalletCertificate()
		require.NoError(t, err)

		// Verify signature was converted
		assert.NotNil(t, walletCert.Signature)

		// Verify signature can be serialized back to same bytes
		serializedSig := walletCert.Signature.Serialize()
		assert.Equal(t, certificate.Signature, serializedSig)
	})

	t.Run("FromWalletCertificate should convert wallet.Certificate to Certificate correctly", func(t *testing.T) {
		// Create a wallet certificate
		typeBytes := tu.GetByte32FromString("test-wallet-cert-type")
		serialBytes := tu.GetByte32FromString("test-wallet-serial")

		walletCert := &wallet.Certificate{
			Type:               typeBytes,
			SerialNumber:       serialBytes,
			Subject:            sampleSubjectPubKey,
			Certifier:          sampleCertifierPubKey,
			RevocationOutpoint: sampleRevocationOutpoint,
			Fields: map[string]string{
				"name":  "Alice",
				"email": "alice@example.com",
			},
			Signature: nil,
		}

		certificate, err := FromWalletCertificate(walletCert)
		require.NoError(t, err)

		// Verify the conversion
		assert.NotNil(t, certificate)
		assert.True(t, certificate.Subject.IsEqual(sampleSubjectPubKey))
		assert.True(t, certificate.Certifier.IsEqual(sampleCertifierPubKey))
		assert.Nil(t, certificate.Signature)

		// Verify type and serial conversion
		expectedType := wallet.StringBase64FromArray(typeBytes)
		expectedSerial := wallet.StringBase64FromArray(serialBytes)
		assert.Equal(t, expectedType, certificate.Type)
		assert.Equal(t, expectedSerial, certificate.SerialNumber)

		// Check fields conversion
		assert.Equal(t, len(walletCert.Fields), len(certificate.Fields))
		for fieldName, fieldValue := range walletCert.Fields {
			certFieldValue := certificate.Fields[wallet.CertificateFieldNameUnder50Bytes(fieldName)]
			assert.Equal(t, fieldValue, string(certFieldValue))
		}

		// Check revocation outpoint conversion
		assert.NotNil(t, certificate.RevocationOutpoint)
		assert.Equal(t, walletCert.RevocationOutpoint.Txid, certificate.RevocationOutpoint.Txid)
		assert.Equal(t, walletCert.RevocationOutpoint.Index, certificate.RevocationOutpoint.Index)
	})

	t.Run("ToWalletCertificate and FromWalletCertificate should be round-trip compatible", func(t *testing.T) {
		originalCert := &Certificate{
			Type:               sampleType,
			SerialNumber:       sampleSerialNumber,
			Subject:            *sampleSubjectPubKey,
			Certifier:          *sampleCertifierPubKey,
			RevocationOutpoint: sampleRevocationOutpoint,
			Fields:             sampleFields,
			Signature:          nil,
		}

		// Convert to wallet certificate and back
		walletCert, err := originalCert.ToWalletCertificate()
		require.NoError(t, err)

		convertedCert, err := FromWalletCertificate(walletCert)
		require.NoError(t, err)

		// Verify they are equivalent
		assert.Equal(t, originalCert.Type, convertedCert.Type)
		assert.Equal(t, originalCert.SerialNumber, convertedCert.SerialNumber)
		assert.True(t, originalCert.Subject.IsEqual(&convertedCert.Subject))
		assert.True(t, originalCert.Certifier.IsEqual(&convertedCert.Certifier))
		assert.Equal(t, originalCert.RevocationOutpoint, convertedCert.RevocationOutpoint)
		assert.Equal(t, originalCert.Fields, convertedCert.Fields)
		assert.Equal(t, originalCert.Signature, convertedCert.Signature)
	})

	t.Run("FromWalletCertificate should handle nil input", func(t *testing.T) {
		certificate, err := FromWalletCertificate(nil)
		assert.Error(t, err)
		assert.Nil(t, certificate)
		assert.Contains(t, err.Error(), "wallet certificate cannot be nil")
	})

	t.Run("ToWalletCertificate should handle invalid base64 in Type", func(t *testing.T) {
		certificate := &Certificate{
			Type:               wallet.StringBase64("invalid-base64!!!"),
			SerialNumber:       sampleSerialNumber,
			Subject:            *sampleSubjectPubKey,
			Certifier:          *sampleCertifierPubKey,
			RevocationOutpoint: sampleRevocationOutpoint,
			Fields:             sampleFields,
			Signature:          nil,
		}

		walletCert, err := certificate.ToWalletCertificate()
		assert.Error(t, err)
		assert.Nil(t, walletCert)
		assert.Contains(t, err.Error(), "invalid certificate type")
	})

	t.Run("ToWalletCertificate should handle invalid base64 in SerialNumber", func(t *testing.T) {
		certificate := &Certificate{
			Type:               sampleType,
			SerialNumber:       wallet.StringBase64("invalid-base64!!!"),
			Subject:            *sampleSubjectPubKey,
			Certifier:          *sampleCertifierPubKey,
			RevocationOutpoint: sampleRevocationOutpoint,
			Fields:             sampleFields,
			Signature:          nil,
		}

		walletCert, err := certificate.ToWalletCertificate()
		assert.Error(t, err)
		assert.Nil(t, walletCert)
		assert.Contains(t, err.Error(), "invalid serial number")
	})
}
