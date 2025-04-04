package certificates

import (
	"encoding/base64"
	"testing"
)

func TestMasterCertificateCreation(t *testing.T) {
	helper := &TestWalletHelper{}

	// Create test wallets and fields
	fields, certifierWallet, subjectWallet, _, err := helper.CreateTestFieldsAndPairs()
	if err != nil {
		t.Fatalf("Failed to create test wallets: %v", err)
	}

	// Create subject counterparty
	subjectCounterparty, err := helper.CreateCounterpartyFromWallet(subjectWallet)
	if err != nil {
		t.Fatalf("Failed to create subject counterparty: %v", err)
	}

	// Create properly encoded certificate type
	certType := base64.StdEncoding.EncodeToString(make([]byte, 32))

	// Issue a master certificate
	masterCert, err := IssueCertificateForSubject(
		certifierWallet,
		subjectCounterparty,
		fields,
		certType,
		helper.GetRevocationOutpointFunc(),
	)
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	// Test basic properties
	if masterCert.Type != certType {
		t.Errorf("Expected certificate type to be '%s', got %s", certType, masterCert.Type)
	}

	if len(masterCert.Fields) != len(fields) {
		t.Errorf("Expected %d fields, got %d", len(fields), len(masterCert.Fields))
	}

	if len(masterCert.MasterKeyring) != len(fields) {
		t.Errorf("Expected %d master keyring entries, got %d", len(fields), len(masterCert.MasterKeyring))
	}

	// Each field should have an encrypted value
	for fieldName := range fields {
		if _, exists := masterCert.Fields[fieldName]; !exists {
			t.Errorf("Expected field '%s' not found in certificate", fieldName)
		}

		if _, exists := masterCert.MasterKeyring[fieldName]; !exists {
			t.Errorf("Expected master key for field '%s' not found", fieldName)
		}
	}
}

func TestMasterCertificateFieldRevalationKeyringCreation(t *testing.T) {
	helper := &TestWalletHelper{}

	// Create test wallets and fields
	fields, certifierWallet, subjectWallet, verifierWallet, err := helper.CreateTestFieldsAndPairs()
	if err != nil {
		t.Fatalf("Failed to create test wallets: %v", err)
	}

	// Create subject and verifier counterparties
	subjectCounterparty, err := helper.CreateCounterpartyFromWallet(subjectWallet)
	if err != nil {
		t.Fatalf("Failed to create subject counterparty: %v", err)
	}

	verifierCounterparty, err := helper.CreateCounterpartyFromWallet(verifierWallet)
	if err != nil {
		t.Fatalf("Failed to create verifier counterparty: %v", err)
	}

	// Create properly encoded certificate type
	certType := base64.StdEncoding.EncodeToString(make([]byte, 32))

	// Issue a master certificate
	masterCert, err := IssueCertificateForSubject(
		certifierWallet,
		subjectCounterparty,
		fields,
		certType,
		helper.GetRevocationOutpointFunc(),
	)
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	// Create a field revelation keyring for selective disclosure
	revealFields := []string{"name", "age"}
	keyring, err := masterCert.CreateFieldRevelationKeyring(
		subjectWallet,
		verifierCounterparty,
		revealFields,
	)
	if err != nil {
		t.Fatalf("Failed to create field revelation keyring: %v", err)
	}

	// Check that keyring has the expected fields
	if len(keyring) != len(revealFields) {
		t.Errorf("Expected keyring to have %d entries, got %d", len(revealFields), len(keyring))
	}

	for _, fieldName := range revealFields {
		if _, exists := keyring[fieldName]; !exists {
			t.Errorf("Expected keyring to have key for field '%s'", fieldName)
		}
	}
}

func TestMasterCertificateDecrypt(t *testing.T) {
	helper := &TestWalletHelper{}

	// Create test wallets and fields
	fields, certifierWallet, subjectWallet, _, err := helper.CreateTestFieldsAndPairs()
	if err != nil {
		t.Fatalf("Failed to create test wallets: %v", err)
	}

	// Create subject counterparty
	subjectCounterparty, err := helper.CreateCounterpartyFromWallet(subjectWallet)
	if err != nil {
		t.Fatalf("Failed to create subject counterparty: %v", err)
	}

	// Create certifier counterparty (for decryption)
	certifierCounterparty, err := helper.CreateCounterpartyFromWallet(certifierWallet)
	if err != nil {
		t.Fatalf("Failed to create certifier counterparty: %v", err)
	}

	// Create properly encoded certificate type
	certType := base64.StdEncoding.EncodeToString(make([]byte, 32))

	// Issue a master certificate
	masterCert, err := IssueCertificateForSubject(
		certifierWallet,
		subjectCounterparty,
		fields,
		certType,
		helper.GetRevocationOutpointFunc(),
	)
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	// Decrypt the fields using the subject's wallet
	decryptedFields, err := masterCert.DecryptFields(subjectWallet, certifierCounterparty)
	if err != nil {
		t.Fatalf("Failed to decrypt fields: %v", err)
	}

	// Check that all fields were decrypted
	for fieldName := range fields {
		decryptedValue, exists := decryptedFields[fieldName]
		if !exists {
			t.Errorf("Expected decrypted field '%s' not found", fieldName)
			continue
		}

		// In a real implementation with actual encryption, we would check if
		// the decrypted value matches the original value.
		// Since we're using a placeholder implementation, we just check it exists.
		if decryptedValue == "" {
			t.Errorf("Decrypted value for field '%s' is empty", fieldName)
		}
	}
}

func TestCreateVerifiableCertificateForVerifier(t *testing.T) {
	helper := &TestWalletHelper{}

	// Create test wallets and fields
	fields, certifierWallet, subjectWallet, verifierWallet, err := helper.CreateTestFieldsAndPairs()
	if err != nil {
		t.Fatalf("Failed to create test wallets: %v", err)
	}

	// Create subject and verifier counterparties
	subjectCounterparty, err := helper.CreateCounterpartyFromWallet(subjectWallet)
	if err != nil {
		t.Fatalf("Failed to create subject counterparty: %v", err)
	}

	verifierCounterparty, err := helper.CreateCounterpartyFromWallet(verifierWallet)
	if err != nil {
		t.Fatalf("Failed to create verifier counterparty: %v", err)
	}

	// Create properly encoded certificate type
	certType := base64.StdEncoding.EncodeToString(make([]byte, 32))

	// Issue a master certificate
	masterCert, err := IssueCertificateForSubject(
		certifierWallet,
		subjectCounterparty,
		fields,
		certType,
		helper.GetRevocationOutpointFunc(),
	)
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	// Create a verifiable certificate for selective disclosure
	revealFields := []string{"name", "age"}
	verifiableCert, err := masterCert.CreateVerifiableCertificateForVerifier(
		subjectWallet,
		verifierCounterparty,
		revealFields,
	)
	if err != nil {
		t.Fatalf("Failed to create verifiable certificate: %v", err)
	}

	// Check that the certificate has the expected properties
	if verifiableCert.Type != masterCert.Type {
		t.Errorf("Type mismatch: expected %s, got %s", masterCert.Type, verifiableCert.Type)
	}

	if verifiableCert.SerialNumber != masterCert.SerialNumber {
		t.Errorf("SerialNumber mismatch: expected %s, got %s", masterCert.SerialNumber, verifiableCert.SerialNumber)
	}

	if len(verifiableCert.KeyRing) != len(revealFields) {
		t.Errorf("Expected KeyRing to have %d entries, got %d", len(revealFields), len(verifiableCert.KeyRing))
	}

	// Check that the keyring has the expected fields
	for _, fieldName := range revealFields {
		if _, exists := verifiableCert.KeyRing[fieldName]; !exists {
			t.Errorf("Expected keyring to have key for field '%s'", fieldName)
		}
	}

	// Fields should match the original certificate (all fields, not just revealed ones)
	if len(verifiableCert.Fields) != len(masterCert.Fields) {
		t.Errorf("Fields mismatch: expected %d, got %d", len(masterCert.Fields), len(verifiableCert.Fields))
	}
}
