package certificates_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func TestMasterCertificate(t *testing.T) {
	subjectPrivateKey, _ := ec.NewPrivateKey()
	certifierPrivateKey, _ := ec.NewPrivateKey()

	mockRevocationOutpoint := &overlay.Outpoint{
		Txid:        chainhash.HashH([]byte("deadbeefdeadbeefdeadbeefdeadbeef00000000000000000000000000000000.1")),
		OutputIndex: 1,
	}

	// Use CompletedProtoWallet for testing
	subjectWallet, _ := certificates.NewCompletedProtoWallet(subjectPrivateKey)
	certifierWallet, _ := certificates.NewCompletedProtoWallet(certifierPrivateKey)

	// Get identity keys with the originator parameter
	subjectIdentityKey, _ := subjectWallet.GetPublicKey(&wallet.GetPublicKeyArgs{IdentityKey: true, ForSelf: false}, "go-sdk")
	certifierIdentityKey, _ := certifierWallet.GetPublicKey(&wallet.GetPublicKeyArgs{IdentityKey: true, ForSelf: false}, "go-sdk")

	subjectCounterparty := wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: subjectIdentityKey.PublicKey}
	certifierCounterparty := wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: certifierIdentityKey.PublicKey}

	t.Run("constructor", func(t *testing.T) {
		t.Run("should construct a MasterCertificate successfully when masterKeyring is valid", func(t *testing.T) {
			// Manually prepare encrypted fields and keyring for basic test
			fieldSymKey := ec.NewSymmetricKeyFromRandom()
			encryptedFieldValueBytes, err := fieldSymKey.Encrypt([]byte("Alice"))
			if err != nil {
				t.Fatalf("Failed to encrypt field value: %v", err)
			}
			encryptedFieldValue := wallet.Base64String(base64.StdEncoding.EncodeToString(encryptedFieldValueBytes))

			encryptedKeyForSubject := wallet.Base64String(base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 3}))

			// We assume we have the same fieldName in both `fields` and `masterKeyring`.
			fields := map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{
				"name": encryptedFieldValue,
			}

			masterKeyring := map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{
				"name": encryptedKeyForSubject,
			}

			// certificate type is 16 random bytes base64 encoded
			certTypeBytes := make([]byte, 16)
			_, _ = rand.Read(certTypeBytes)
			certType := wallet.Base64String(base64.StdEncoding.EncodeToString(certTypeBytes))

			serialNumberBytes := make([]byte, 16)
			_, _ = rand.Read(serialNumberBytes)
			serialNumber := wallet.Base64String(base64.StdEncoding.EncodeToString(serialNumberBytes))

			baseCert := &certificates.Certificate{
				Type:               certType,
				SerialNumber:       serialNumber,
				Subject:            *subjectIdentityKey.PublicKey,
				Certifier:          *certifierIdentityKey.PublicKey,
				RevocationOutpoint: mockRevocationOutpoint,
				Fields:             fields,
			}

			masterCert, err := certificates.NewMasterCertificate(baseCert, masterKeyring)

			if err != nil {
				t.Fatalf("Constructor failed unexpectedly: %v", err)
			}
			if masterCert == nil {
				t.Fatal("Constructor returned nil certificate")
			}
			if !reflect.DeepEqual(masterCert.Fields, fields) {
				t.Errorf("Expected fields %v, got %v", fields, masterCert.Fields)
			}
			if !reflect.DeepEqual(masterCert.MasterKeyring, masterKeyring) {
				t.Errorf("Expected masterKeyring %v, got %v", masterKeyring, masterCert.MasterKeyring)
			}
			// Compare public keys by compressed byte representation
			if !bytes.Equal(masterCert.Subject.Compressed(), subjectIdentityKey.PublicKey.Compressed()) {
				t.Errorf("Expected subject %s, got %s", hex.EncodeToString(subjectIdentityKey.PublicKey.Compressed()), hex.EncodeToString(masterCert.Subject.Compressed()))
			}
			if !bytes.Equal(masterCert.Certifier.Compressed(), certifierIdentityKey.PublicKey.Compressed()) {
				t.Errorf("Expected certifier %s, got %s", hex.EncodeToString(certifierIdentityKey.PublicKey.Compressed()), hex.EncodeToString(masterCert.Certifier.Compressed()))
			}
		})

		t.Run("should return error if masterKeyring is missing a key for any field", func(t *testing.T) {
			fields := map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{"name": utils.RandomBase64(16)}
			masterKeyring := map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{} // Intentionally empty

			baseCert := &certificates.Certificate{
				Type:               utils.RandomBase64(16),
				SerialNumber:       utils.RandomBase64(16),
				Subject:            *subjectIdentityKey.PublicKey,
				Certifier:          *certifierIdentityKey.PublicKey,
				RevocationOutpoint: mockRevocationOutpoint,
				Fields:             fields,
			}

			_, err := certificates.NewMasterCertificate(baseCert, masterKeyring)
			if err == nil {
				t.Fatal("Expected an error due to missing key in masterKeyring, but got nil")
			}
			// Check for specific error message
			expectedErr := certificates.ErrMissingMasterKeyring
			if err.Error() != expectedErr.Error() {
				t.Errorf("Expected error '%s', but got: %v", expectedErr, err)
			}
		})
	})

	t.Run("DecryptFields (static)", func(t *testing.T) {
		// Define issuedCert at the start of this test group
		plainFieldsStr := map[string]string{
			"name":       "Alice",
			"email":      "alice@example.com",
			"department": "Engineering",
		}
		issueCert, err := certificates.IssueCertificateForSubject(
			certifierWallet.ProtoWallet,
			subjectCounterparty,
			plainFieldsStr,
			string(utils.RandomBase64(32)), // Use valid Base64 for type
			nil,                            // No revocation func
			"",                             // No specific serial
		)
		if err != nil {
			t.Fatalf("Setup for DecryptFields failed: Failed to issue certificate: %v", err)
		}

		t.Run("should decrypt all fields correctly using subject wallet", func(t *testing.T) {
			decrypted, err := certificates.DecryptFields(
				subjectWallet.ProtoWallet,
				issueCert.MasterKeyring, // Uses issuedCert from outer scope
				issueCert.Fields,        // Uses issuedCert from outer scope
				certifierCounterparty,   // Certifier was counterparty for encryption
				false,
				"",
			)

			if err != nil {
				t.Fatalf("DecryptFields failed unexpectedly: %v", err)
			}

			// Convert expected map[string]string to map[CertificateFieldNameUnder50Bytes]string
			expectedDecrypted := make(map[wallet.CertificateFieldNameUnder50Bytes]string)
			for k, v := range plainFieldsStr {
				expectedDecrypted[wallet.CertificateFieldNameUnder50Bytes(k)] = v
			}

			if !reflect.DeepEqual(decrypted, expectedDecrypted) {
				t.Errorf("Decryption result mismatch.\nExpected: %v\nGot:      %v", expectedDecrypted, decrypted)
			}
		})

		t.Run("should return error if masterKeyring is nil or empty", func(t *testing.T) {
			_, err := certificates.DecryptFields(
				subjectWallet.ProtoWallet,
				nil,              // Test nil keyring
				issueCert.Fields, // Uses issuedCert from outer scope
				certifierCounterparty,
				false,
				"",
			)
			if err == nil {
				t.Fatal("Expected error for nil masterKeyring, got nil")
			}
			if !errors.Is(err, certificates.ErrMissingMasterKeyring) {
				t.Errorf("Expected ErrMissingMasterKeyring, got %v", err)
			}

			_, err = certificates.DecryptFields(
				subjectWallet.ProtoWallet,
				map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{}, // Test empty keyring
				issueCert.Fields, // Uses issuedCert from outer scope
				certifierCounterparty,
				false,
				"",
			)
			if err == nil {
				t.Fatal("Expected error for empty masterKeyring, got nil")
			}
			// Check if the error message contains the expected substring for missing key
			if !strings.Contains(err.Error(), certificates.ErrMissingMasterKeyring.Error()) {
				t.Errorf("Expected error containing 'key not found in keyring', got %v", err)
			}
		})

		t.Run("should return error if decryption fails for any field", func(t *testing.T) {
			// Create a bad keyring manually
			badMasterKeyring := make(map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String)
			for k := range issueCert.Fields { // Uses issuedCert from outer scope
				badMasterKeyring[k] = utils.RandomBase64(64) // Provide structurally valid (>48 bytes) but incorrect key data
			}

			_, err := certificates.DecryptFields(
				subjectWallet.ProtoWallet,
				badMasterKeyring,
				issueCert.Fields, // Uses issuedCert from outer scope
				certifierCounterparty,
				false,
				"",
			)
			if err == nil {
				t.Fatal("Expected decryption error due to bad keyring, got nil")
			}
			// Check if the error message contains the expected underlying crypto error
			if !strings.Contains(err.Error(), "message authentication failed") {
				t.Errorf("Expected error containing 'message authentication failed', got: %v", err)
			}
		})
	})

	t.Run("CreateKeyringForVerifier (static)", func(t *testing.T) {
		// Define issuedCert at the start of this test group
		plainFieldsKrStr := map[string]string{
			"name":       "Alice",
			"email":      "alice@example.com",
			"department": "Engineering",
		}
		issueCert, err := certificates.IssueCertificateForSubject(
			certifierWallet.ProtoWallet,
			subjectCounterparty,
			plainFieldsKrStr,
			string(utils.RandomBase64(32)), // Use valid Base64 for type
			nil,
			"",
		)
		if err != nil {
			t.Fatalf("Setup for CreateKeyringForVerifier failed: Failed to issue certificate: %v", err)
		}

		// Define verifier within this scope too
		verifierPrivateKey, _ := ec.NewPrivateKey()
		// Use a standard ProtoWallet for the verifier
		verifierWallet, _ := wallet.NewProtoWallet(wallet.ProtoWalletArgs{Type: wallet.ProtoWalletArgsTypePrivateKey, PrivateKey: verifierPrivateKey})
		verifierIdentityKey, _ := verifierWallet.GetPublicKey(&wallet.GetPublicKeyArgs{IdentityKey: true}, "")
		verifierCounterparty := wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: verifierIdentityKey.PublicKey}

		t.Run("should create a verifier keyring for specified fields", func(t *testing.T) {
			fieldsToReveal := []wallet.CertificateFieldNameUnder50Bytes{"name"}

			keyringForVerifier, err := certificates.CreateKeyringForVerifier(
				subjectWallet.ProtoWallet,
				certifierCounterparty,
				verifierCounterparty,
				issueCert.Fields, // Uses issuedCert from outer scope
				fieldsToReveal,
				issueCert.MasterKeyring, // Uses issuedCert from outer scope
				issueCert.SerialNumber,  // Uses issuedCert from outer scope
				false,
				"",
			)

			if err != nil {
				t.Fatalf("CreateKeyringForVerifier failed unexpectedly: %v", err)
			}

			if len(keyringForVerifier) != 1 {
				t.Errorf("Expected keyring to have 1 key, got %d", len(keyringForVerifier))
			}
			if _, exists := keyringForVerifier["name"]; !exists {
				t.Error("Expected keyring to contain 'name' key")
			}

			// TODO: When VerifiableCertificate is implemented, create one and test decryption
			// by the verifierWallet using the keyringForVerifier.
		})

		t.Run("should return error if fields to reveal are not a subset", func(t *testing.T) {
			fieldsToReveal := []wallet.CertificateFieldNameUnder50Bytes{"nonexistent_field"}
			_, err := certificates.CreateKeyringForVerifier(
				subjectWallet.ProtoWallet,
				certifierCounterparty,
				verifierCounterparty,
				issueCert.Fields, // Uses issuedCert from outer scope
				fieldsToReveal,
				issueCert.MasterKeyring, // Uses issuedCert from outer scope
				issueCert.SerialNumber,  // Uses issuedCert from outer scope
				false,
				"",
			)

			if err == nil {
				t.Fatal("Expected error for nonexistent field, got nil")
			}
			if !errors.Is(err, certificates.ErrFieldNotFound) {
				t.Errorf("Expected ErrFieldNotFound, got: %v", err)
			}
		})

		t.Run("should return error if the master key fails to decrypt", func(t *testing.T) {
			// Tamper with the master keyring
			tamperedMasterKeyring := make(map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String)
			for k, v := range issueCert.MasterKeyring { // Uses issuedCert from outer scope
				if k == "name" {
					tamperedMasterKeyring[k] = utils.RandomBase64(64) // Provide structurally valid (>48 bytes) but incorrect key data
				} else {
					tamperedMasterKeyring[k] = v
				}
			}

			fieldsToReveal := []wallet.CertificateFieldNameUnder50Bytes{"name"}
			_, err := certificates.CreateKeyringForVerifier(
				subjectWallet.ProtoWallet,
				certifierCounterparty,
				verifierCounterparty,
				issueCert.Fields, // Uses issuedCert from outer scope
				fieldsToReveal,
				tamperedMasterKeyring,  // Use tampered keyring
				issueCert.SerialNumber, // Uses issuedCert from outer scope
				false,
				"",
			)

			if err == nil {
				t.Fatal("Expected error due to tampered master key, got nil")
			}
			// DecryptField should return a wrapped error containing ErrDecryptionFailed
			if !errors.Is(err, certificates.ErrDecryptionFailed) {
				t.Errorf("Expected error wrapping ErrDecryptionFailed, got: %v", err)
			}
			// Check if the error message contains the expected underlying crypto error
			if !strings.Contains(err.Error(), "message authentication failed") {
				t.Errorf("Expected error containing 'message authentication failed', got: %v", err)
			}
		})

		t.Run("should support 'anyone' and 'self' counterparties for verifier", func(t *testing.T) {
			fieldsToReveal := []wallet.CertificateFieldNameUnder50Bytes{"email"}

			// Test 'anyone'
			keyringAnyone, errAnyone := certificates.CreateKeyringForVerifier(
				subjectWallet.ProtoWallet,
				certifierCounterparty,
				wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone},
				issueCert.Fields, // Uses issuedCert from outer scope
				fieldsToReveal,
				issueCert.MasterKeyring, // Uses issuedCert from outer scope
				issueCert.SerialNumber,  // Uses issuedCert from outer scope
				false,
				"",
			)
			if errAnyone != nil {
				t.Fatalf("CreateKeyringForVerifier failed for 'anyone': %v", errAnyone)
			}
			if _, exists := keyringAnyone["email"]; !exists {
				t.Error("Keyring for 'anyone' missing 'email' key")
			}

			// Test 'self'
			keyringSelf, errSelf := certificates.CreateKeyringForVerifier(
				subjectWallet.ProtoWallet,
				certifierCounterparty,
				wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
				issueCert.Fields, // Uses issuedCert from outer scope
				fieldsToReveal,
				issueCert.MasterKeyring, // Uses issuedCert from outer scope
				issueCert.SerialNumber,  // Uses issuedCert from outer scope
				false,
				"",
			)
			if errSelf != nil {
				t.Fatalf("CreateKeyringForVerifier failed for 'self': %v", errSelf)
			}
			if _, exists := keyringSelf["email"]; !exists {
				t.Error("Keyring for 'self' missing 'email' key")
			}
		})
	})

	t.Run("IssueCertificateForSubject (static)", func(t *testing.T) {
		t.Run("should issue a valid MasterCertificate", func(t *testing.T) {
			newPlaintextFields := map[string]string{
				"project":        "Top Secret",
				"clearanceLevel": "High",
			}

			revocationFuncCalled := false
			mockRevocationFunc := func(serial string) (*overlay.Outpoint, error) {
				revocationFuncCalled = true
				return mockRevocationOutpoint, nil
			}

			newCert, err := certificates.IssueCertificateForSubject(
				certifierWallet.ProtoWallet,
				subjectCounterparty,
				newPlaintextFields,
				string(utils.RandomBase64(32)),
				mockRevocationFunc,
				"",
			)

			if err != nil {
				t.Fatalf("IssueCertificateForSubject failed: %v", err)
			}
			if newCert == nil {
				t.Fatal("IssueCertificateForSubject returned nil certificate")
			}

			// Check fields are encrypted (basic Base64 check)
			for fieldNameStr := range newPlaintextFields {
				fieldName := wallet.CertificateFieldNameUnder50Bytes(fieldNameStr)
				if _, err := base64.StdEncoding.DecodeString(string(newCert.Fields[fieldName])); err != nil {
					t.Errorf("Field '%s' value is not valid Base64: %s", fieldName, newCert.Fields[fieldName])
				}
			}
			// Check master keyring keys are encrypted
			for fieldNameStr := range newPlaintextFields {
				fieldName := wallet.CertificateFieldNameUnder50Bytes(fieldNameStr)
				if _, err := base64.StdEncoding.DecodeString(string(newCert.MasterKeyring[fieldName])); err != nil {
					t.Errorf("MasterKeyring key for '%s' is not valid Base64: %s", fieldName, newCert.MasterKeyring[fieldName])
				}
			}

			if !reflect.DeepEqual(newCert.RevocationOutpoint, mockRevocationOutpoint) {
				t.Errorf("Expected revocation outpoint %v, got %v", mockRevocationOutpoint, newCert.RevocationOutpoint)
			}
			if len(newCert.Signature) == 0 {
				t.Error("Expected certificate signature to be present")
			}
			if !revocationFuncCalled {
				t.Error("Expected mockRevocationFunc to be called")
			}
		})

		t.Run("should allow passing a custom serial number", func(t *testing.T) {
			customSerialNumber := utils.RandomBase64(32)
			newPlaintextFields := map[string]string{"status": "Approved"}
			newCert, err := certificates.IssueCertificateForSubject(
				certifierWallet.ProtoWallet,
				subjectCounterparty,
				newPlaintextFields,
				string(utils.RandomBase64(32)),
				nil,
				string(customSerialNumber),
			)

			if err != nil {
				t.Fatalf("IssueCertificateForSubject with custom SN failed: %v", err)
			}
			if newCert.SerialNumber != customSerialNumber {
				t.Errorf("Expected serial number %s, got %s", customSerialNumber, newCert.SerialNumber)
			}
		})

		t.Run("should allow issuing and decrypting a self-signed certificate", func(t *testing.T) {
			// Use subject's wallet as certifier
			selfSignedFields := map[string]string{
				"owner":        "Bob",
				"organization": "SelfCo",
			}
			selfSignedCert, err := certificates.IssueCertificateForSubject(
				subjectWallet.ProtoWallet,                              // Subject is certifier
				wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}, // Subject is self
				selfSignedFields,
				string(utils.RandomBase64(32)),
				nil,
				"",
			)

			if err != nil {
				t.Fatalf("Issuing self-signed certificate failed: %v", err)
			}

			// Decrypt using the same wallet
			decrypted, err := certificates.DecryptFields(
				subjectWallet.ProtoWallet,
				selfSignedCert.MasterKeyring,
				selfSignedCert.Fields,
				wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}, // Counterparty is self
				false,
				"",
			)

			if err != nil {
				t.Fatalf("Decrypting self-signed certificate failed: %v", err)
			}

			// Convert expected map
			expectedDecrypted := make(map[wallet.CertificateFieldNameUnder50Bytes]string)
			for k, v := range selfSignedFields {
				expectedDecrypted[wallet.CertificateFieldNameUnder50Bytes(k)] = v
			}

			if !reflect.DeepEqual(decrypted, expectedDecrypted) {
				t.Errorf("Self-signed decryption mismatch.\nExpected: %v\nGot:      %v", expectedDecrypted, decrypted)
			}
		})
	})
}
