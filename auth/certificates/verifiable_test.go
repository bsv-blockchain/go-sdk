package certificates

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestVerifiableCertificate(t *testing.T) {
	// Set up test keys
	subjectPrivateKey, _ := ec.NewPrivateKey()
	subjectIdentityKey := subjectPrivateKey.PubKey()
	certifierPrivateKey, _ := ec.NewPrivateKey()
	certifierIdentityKey := certifierPrivateKey.PubKey()
	verifierPrivateKey, _ := ec.NewPrivateKey()
	verifierIdentityKey := verifierPrivateKey.PubKey()

	// Create wallets
	subjectWallet, _ := NewCompletedProtoWallet(subjectPrivateKey)
	verifierWallet, _ := NewCompletedProtoWallet(verifierPrivateKey)

	// Sample data
	sampleType := wallet.Base64String(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	sampleSerialNumber := wallet.Base64String(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)))
	sampleRevocationOutpoint := &overlay.Outpoint{
		Txid:        chainhash.HashH([]byte("deadbeefdeadbeefdeadbeefdeadbeef00000000000000000000000000000000.1")),
		OutputIndex: 1,
	}

	// Plaintext fields to encrypt
	plaintextFields := map[string]string{
		"name":         "Alice",
		"email":        "alice@example.com",
		"organization": "Example Corp",
	}

	// Setup certifier and verifier counterparties
	certifierCounterparty := wallet.Counterparty{
		Type:         wallet.CounterpartyTypeOther,
		Counterparty: certifierIdentityKey,
	}
	verifierCounterparty := wallet.Counterparty{
		Type:         wallet.CounterpartyTypeOther,
		Counterparty: verifierIdentityKey,
	}

	t.Run("constructor", func(t *testing.T) {
		t.Run("should create a VerifiableCertificate with all required properties", func(t *testing.T) {
			// Convert plaintext fields to CertificateFieldNameUnder50Bytes format
			fieldsForEncryption := make(map[wallet.CertificateFieldNameUnder50Bytes]string)
			for k, v := range plaintextFields {
				fieldsForEncryption[wallet.CertificateFieldNameUnder50Bytes(k)] = v
			}

			// Create certificate fields and master keyring
			fieldResult, err := CreateCertificateFields(
				subjectWallet.ProtoWallet,
				certifierCounterparty,
				fieldsForEncryption,
				false,
				"",
			)
			if err != nil {
				t.Fatalf("Failed to create certificate fields: %v", err)
			}

			certificateFields := fieldResult.CertificateFields
			masterKeyring := fieldResult.MasterKeyring

			// Create keyring for verifier
			fieldNames := make([]wallet.CertificateFieldNameUnder50Bytes, 0, len(certificateFields))
			for fieldName := range certificateFields {
				fieldNames = append(fieldNames, fieldName)
			}

			keyringForVerifier, err := CreateKeyringForVerifier(
				subjectWallet.ProtoWallet,
				certifierCounterparty,
				verifierCounterparty,
				certificateFields,
				fieldNames,
				masterKeyring,
				sampleSerialNumber,
				false,
				"",
			)
			if err != nil {
				t.Fatalf("Failed to create keyring for verifier: %v", err)
			}

			// Convert keyring to expected format
			keyringMap := make(map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String)
			for k, v := range keyringForVerifier {
				keyringMap[k] = wallet.Base64String(v)
			}

			// Create VerifiableCertificate
			baseCert := &Certificate{
				Type:               sampleType,
				SerialNumber:       sampleSerialNumber,
				Subject:            *subjectIdentityKey,
				Certifier:          *certifierIdentityKey,
				RevocationOutpoint: sampleRevocationOutpoint,
				Fields:             certificateFields,
				Signature:          nil,
			}

			verifiableCert := NewVerifiableCertificate(baseCert, keyringMap)

			// Assertions
			if verifiableCert == nil {
				t.Fatal("Expected verifiableCert to be created, got nil")
			}
			if verifiableCert.Type != sampleType {
				t.Errorf("Expected type %s, got %s", sampleType, verifiableCert.Type)
			}
			if verifiableCert.SerialNumber != sampleSerialNumber {
				t.Errorf("Expected serialNumber %s, got %s", sampleSerialNumber, verifiableCert.SerialNumber)
			}
			if !verifiableCert.Subject.IsEqual(subjectIdentityKey) {
				t.Errorf("Expected subject %v, got %v", subjectIdentityKey, verifiableCert.Subject)
			}
			if !verifiableCert.Certifier.IsEqual(certifierIdentityKey) {
				t.Errorf("Expected certifier %v, got %v", certifierIdentityKey, verifiableCert.Certifier)
			}
			if verifiableCert.RevocationOutpoint == nil || verifiableCert.RevocationOutpoint.Txid != sampleRevocationOutpoint.Txid {
				t.Errorf("Expected revocationOutpoint %v, got %v", sampleRevocationOutpoint, verifiableCert.RevocationOutpoint)
			}
			if verifiableCert.Fields == nil {
				t.Error("Expected fields to be defined")
			}
			if verifiableCert.Keyring == nil {
				t.Error("Expected keyring to be defined")
			}
		})
	})

	t.Run("decryptFields", func(t *testing.T) {
		var verifiableCert *VerifiableCertificate

		// Setup a fresh VerifiableCertificate for each test
		setupVerifiableCert := func(t *testing.T) {
			// Convert plaintext fields to CertificateFieldNameUnder50Bytes format
			fieldsForEncryption := make(map[wallet.CertificateFieldNameUnder50Bytes]string)
			for k, v := range plaintextFields {
				fieldsForEncryption[wallet.CertificateFieldNameUnder50Bytes(k)] = v
			}

			// Create certificate fields and master keyring
			fieldResult, err := CreateCertificateFields(
				subjectWallet.ProtoWallet,
				certifierCounterparty,
				fieldsForEncryption,
				false,
				"",
			)
			if err != nil {
				t.Fatalf("Failed to create certificate fields: %v", err)
			}

			certificateFields := fieldResult.CertificateFields
			masterKeyring := fieldResult.MasterKeyring

			// Create keyring for verifier
			fieldNames := make([]wallet.CertificateFieldNameUnder50Bytes, 0, len(certificateFields))
			for fieldName := range certificateFields {
				fieldNames = append(fieldNames, fieldName)
			}

			keyringForVerifier, err := CreateKeyringForVerifier(
				subjectWallet.ProtoWallet,
				certifierCounterparty,
				verifierCounterparty,
				certificateFields,
				fieldNames,
				masterKeyring,
				sampleSerialNumber,
				false,
				"",
			)
			if err != nil {
				t.Fatalf("Failed to create keyring for verifier: %v", err)
			}

			// Convert keyring to expected format
			keyringMap := make(map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String)
			for k, v := range keyringForVerifier {
				keyringMap[k] = wallet.Base64String(v)
			}

			// Create VerifiableCertificate
			baseCert := &Certificate{
				Type:               sampleType,
				SerialNumber:       sampleSerialNumber,
				Subject:            *subjectIdentityKey,
				Certifier:          *certifierIdentityKey,
				RevocationOutpoint: sampleRevocationOutpoint,
				Fields:             certificateFields,
				Signature:          nil,
			}

			verifiableCert = NewVerifiableCertificate(baseCert, keyringMap)
		}

		t.Run("should decrypt fields successfully when provided the correct verifier wallet and keyring", func(t *testing.T) {
			setupVerifiableCert(t)

			// Decrypt fields
			decrypted, err := verifiableCert.DecryptFields(
				verifierWallet,
				false,
				"",
			)
			if err != nil {
				t.Fatalf("DecryptFields failed: %v", err)
			}

			// Compare decrypted fields with original plaintext
			if len(decrypted) != len(plaintextFields) {
				t.Errorf("Expected %d decrypted fields, got %d", len(plaintextFields), len(decrypted))
			}
			for field, value := range plaintextFields {
				if decrypted[field] != value {
					t.Errorf("Expected %s for field %s, got %s", value, field, decrypted[field])
				}
			}
		})

		t.Run("should fail if the verifier wallet does not have the correct private key (wrong key)", func(t *testing.T) {
			setupVerifiableCert(t)

			// Create a wallet with wrong key
			wrongPrivateKey, _ := ec.NewPrivateKey()
			wrongWallet, _ := NewCompletedProtoWallet(wrongPrivateKey)

			// Decrypt should fail
			_, err := verifiableCert.DecryptFields(
				wrongWallet,
				false,
				"",
			)
			if err == nil {
				t.Fatal("Expected DecryptFields to fail with wrong wallet, but it succeeded")
			}
			if !strings.Contains(err.Error(), "failed to decrypt selectively revealed certificate fields using keyring") {
				t.Errorf("Expected error to contain failure message, got: %v", err)
			}
		})

		t.Run("should fail if the keyring is empty or missing keys", func(t *testing.T) {
			setupVerifiableCert(t)

			// Create a new VerifiableCertificate but with an empty keyring
			emptyKeyringCert := NewVerifiableCertificate(
				&Certificate{
					Type:               verifiableCert.Type,
					SerialNumber:       verifiableCert.SerialNumber,
					Subject:            verifiableCert.Subject,
					Certifier:          verifiableCert.Certifier,
					RevocationOutpoint: verifiableCert.RevocationOutpoint,
					Fields:             verifiableCert.Fields,
					Signature:          verifiableCert.Signature,
				},
				nil, // empty keyring
			)

			// Decrypt should fail due to empty keyring
			_, err := emptyKeyringCert.DecryptFields(
				verifierWallet,
				false,
				"",
			)
			if err == nil {
				t.Fatal("Expected DecryptFields to fail with empty keyring, but it succeeded")
			}
			expectedErrMsg := "a keyring is required to decrypt certificate fields for the verifier"
			if err.Error() != expectedErrMsg {
				t.Errorf("Expected error message '%s', got: %v", expectedErrMsg, err)
			}
		})

		t.Run("should fail if the encrypted field or its key is tampered", func(t *testing.T) {
			setupVerifiableCert(t)

			// Tamper the keyring by changing a key
			tamperedKeyring := make(map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String)
			for k := range verifiableCert.Keyring {
				// Modify the "name" key to be invalid
				if k == "name" {
					tamperedKeyring[k] = wallet.Base64String(base64.StdEncoding.EncodeToString([]byte{9, 9, 9, 9}))
				} else {
					tamperedKeyring[k] = verifiableCert.Keyring[k]
				}
			}

			// Replace the keyring
			verifiableCert.Keyring = tamperedKeyring

			// Decrypt should fail due to tampered keyring
			_, err := verifiableCert.DecryptFields(
				verifierWallet,
				false,
				"",
			)
			if err == nil {
				t.Fatal("Expected DecryptFields to fail with tampered keyring, but it succeeded")
			}
			if !strings.Contains(err.Error(), "failed to decrypt selectively revealed certificate fields using keyring") {
				t.Errorf("Expected error to contain failure message, got: %v", err)
			}
			require.Error(t, err)
		})

		t.Run("should be able to decrypt fields using the anyone wallet", func(t *testing.T) {
			// Convert plaintext fields to CertificateFieldNameUnder50Bytes format
			fieldsForEncryption := make(map[wallet.CertificateFieldNameUnder50Bytes]string)
			for k, v := range plaintextFields {
				fieldsForEncryption[wallet.CertificateFieldNameUnder50Bytes(k)] = v
			}

			// Create certificate fields and master keyring
			fieldResult, err := CreateCertificateFields(
				subjectWallet.ProtoWallet,
				certifierCounterparty,
				fieldsForEncryption,
				false,
				"",
			)
			if err != nil {
				t.Fatalf("Failed to create certificate fields: %v", err)
			}

			certificateFields := fieldResult.CertificateFields
			masterKeyring := fieldResult.MasterKeyring

			// Create keyring for "anyone"
			fieldNames := make([]wallet.CertificateFieldNameUnder50Bytes, 0, len(certificateFields))
			for fieldName := range certificateFields {
				fieldNames = append(fieldNames, fieldName)
			}

			// Use "anyone" counterparty
			anyoneCounterparty := wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone}

			keyringForVerifier, err := CreateKeyringForVerifier(
				subjectWallet.ProtoWallet,
				certifierCounterparty,
				anyoneCounterparty,
				certificateFields,
				fieldNames,
				masterKeyring,
				sampleSerialNumber,
				false,
				"",
			)
			if err != nil {
				t.Fatalf("Failed to create keyring for anyone: %v", err)
			}

			// Convert keyring to expected format
			keyringMap := make(map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String)
			for k, v := range keyringForVerifier {
				keyringMap[k] = wallet.Base64String(v)
			}

			// Create certificate with "anyone" certifier
			anyoneWallet, err := NewCompletedProtoWallet(nil)
			if err != nil {
				t.Fatalf("Failed to create anyone wallet: %v", err)
			}

			anyoneCertPubKey, err := anyoneWallet.GetPublicKey(t.Context(), wallet.GetPublicKeyArgs{IdentityKey: true}, "")
			if err != nil {
				t.Fatalf("Failed to get anyone public key: %v", err)
			}

			baseCert := &Certificate{
				Type:               sampleType,
				SerialNumber:       sampleSerialNumber,
				Subject:            *subjectIdentityKey,
				Certifier:          *anyoneCertPubKey.PublicKey,
				RevocationOutpoint: sampleRevocationOutpoint,
				Fields:             certificateFields,
				Signature:          nil,
			}

			anyoneCert := NewVerifiableCertificate(baseCert, keyringMap)

			// Decrypt with "anyone" wallet
			decrypted, err := anyoneCert.DecryptFields(
				anyoneWallet,
				false,
				"",
			)
			if err != nil {
				t.Fatalf("DecryptFields with anyone wallet failed: %v", err)
			}

			// Compare decrypted fields with original plaintext
			if len(decrypted) != len(plaintextFields) {
				t.Errorf("Expected %d decrypted fields, got %d", len(plaintextFields), len(decrypted))
			}
			for field, value := range plaintextFields {
				if decrypted[field] != value {
					t.Errorf("Expected %s for field %s, got %s", value, field, decrypted[field])
				}
			}
		})
	})
}
