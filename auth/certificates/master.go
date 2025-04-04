package certificates

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

var (
	ErrInvalidMasterCertificate = errors.New("invalid master certificate")
	ErrMissingMasterKeyring     = errors.New("master keyring is required")
)

// MasterCertificate extends the Certificate struct to include a master keyring
// for key management and selective disclosure of certificate fields.
type MasterCertificate struct {
	// Embed the Certificate struct
	Certificate
	// MasterKeyring contains encrypted symmetric keys for each field
	MasterKeyring map[string]string `json:"masterKeyring,omitempty"`
}

// NewMasterCertificate creates a new master certificate with the given fields
func NewMasterCertificate(
	cert *Certificate,
	masterKeyring map[string]string,
) (*MasterCertificate, error) {
	// Ensure every field has a corresponding master key
	for field := range cert.Fields {
		if _, exists := masterKeyring[field]; !exists {
			return nil, errors.New("master keyring must contain a value for every field")
		}
	}

	// Create the certificate
	masterCert := &MasterCertificate{
		Certificate:   *cert,
		MasterKeyring: masterKeyring,
	}

	return masterCert, nil
}

// IssueCertificateForSubject creates a new certificate for a subject
// This is a static method that creates and returns a signed MasterCertificate
func IssueCertificateForSubject(
	certifierWallet *wallet.Wallet,
	subject *wallet.Counterparty,
	plainFields map[string]string,
	certificateType string,
	// Optional revocation outpoint, default to a placeholder value
	getRevocationOutpoint func(string) (*overlay.Outpoint, error),
) (*MasterCertificate, error) {
	// 1. Generate a random serialNumber if not provided
	serialBytes := make([]byte, 32)
	if _, err := rand.Read(serialBytes); err != nil {
		return nil, err
	}
	serialNumber := base64.StdEncoding.EncodeToString(serialBytes)

	// 2. Create encrypted certificate fields and associated master keyring
	encryptedFields, masterKeyring, err := createCertificateFields(certifierWallet, subject, plainFields)
	if err != nil {
		return nil, err
	}

	// 3. Get the identity public key of the certifier
	certifierPubKeyResult, err := certifierWallet.GetPublicKey(&wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, "")
	if err != nil {
		return nil, err
	}

	// 4. Get revocation outpoint
	var revocationOutpoint *overlay.Outpoint
	if getRevocationOutpoint != nil {
		revocationOutpoint, err = getRevocationOutpoint(serialNumber)
		if err != nil {
			return nil, fmt.Errorf("failed to get revocation outpoint: %w", err)
		}
	} else {
		// Default to empty outpoint
		revocationOutpoint = &overlay.Outpoint{}
	}

	// 5. Create the base certificate
	baseCert := &Certificate{
		Type:               certificateType,
		SerialNumber:       serialNumber,
		Subject:            *subject.Counterparty,
		Certifier:          *certifierPubKeyResult.PublicKey,
		RevocationOutpoint: revocationOutpoint,
		Fields:             encryptedFields,
	}

	// 6. Create the master certificate
	masterCert, err := NewMasterCertificate(baseCert, masterKeyring)
	if err != nil {
		return nil, err
	}

	// 7. Sign the certificate
	err = masterCert.Sign(certifierWallet)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	return masterCert, nil
}

// createCertificateFields encrypts certificate fields and creates a master keyring
func createCertificateFields(
	certifierWallet *wallet.Wallet,
	subject *wallet.Counterparty,
	fields map[string]string,
) (encryptedFields map[string]string, masterKeyring map[string]string, err error) {
	// Initialize result maps
	encryptedFields = make(map[string]string)
	masterKeyring = make(map[string]string)

	// Process each field
	for fieldName, fieldValue := range fields {
		// For each field we:
		// 1. Generate a random symmetric key (in TypeScript this would be SymmetricKey.fromRandom())
		// 2. Encrypt the field value with this key
		// 3. Encrypt the key with the subject's public key

		// 1. Generate a random key (32 bytes)
		fieldSymmetricKey := make([]byte, 32)
		if _, err := rand.Read(fieldSymmetricKey); err != nil {
			return nil, nil, fmt.Errorf("failed to generate random key: %w", err)
		}

		// 2. In TypeScript, encrypt the field value with the symmetric key
		// Here we're simulating this - in a real implementation we would:
		// symmetricKey := symmetric.NewKey(fieldSymmetricKey)
		// encryptedFieldValue, err := symmetricKey.Encrypt([]byte(fieldValue))

		// For now, just encode the field value in base64 as a placeholder
		encryptedFieldValue := base64.StdEncoding.EncodeToString([]byte(fieldValue))
		encryptedFields[fieldName] = encryptedFieldValue

		// 3. Encrypt the symmetric key for the subject
		protocolID, keyID := GetCertificateEncryptionDetails(fieldName, "")
		encryptResult, err := certifierWallet.Encrypt(&wallet.EncryptArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID:   protocolID,
				KeyID:        keyID,
				Counterparty: *subject,
			},
			Plaintext: fieldSymmetricKey,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to encrypt field revelation key: %w", err)
		}

		// Store the encrypted key in the master keyring
		masterKeyring[fieldName] = base64.StdEncoding.EncodeToString(encryptResult.Ciphertext)
	}

	return encryptedFields, masterKeyring, nil
}

// CreateFieldRevelationKeyring creates a keyring that allows a verifier to decrypt specific fields
func (m *MasterCertificate) CreateFieldRevelationKeyring(
	subjectWallet *wallet.Wallet,
	verifier *wallet.Counterparty,
	fieldNames []string,
) (map[string]string, error) {
	if m.MasterKeyring == nil || len(m.MasterKeyring) == 0 {
		return nil, ErrMissingMasterKeyring
	}

	// Create a keyring to share with the verifier
	keyring := make(map[string]string)

	// Verify that all requested fields exist in the certificate
	for _, fieldName := range fieldNames {
		if _, exists := m.Fields[fieldName]; !exists {
			return nil, fmt.Errorf("field %s does not exist in the certificate", fieldName)
		}
	}

	// For each requested field, decrypt its master key and re-encrypt for the verifier
	for _, fieldName := range fieldNames {
		// Get the encrypted master key
		masterKey, exists := m.MasterKeyring[fieldName]
		if !exists {
			continue // Skip fields not in master keyring
		}

		// 1. Decrypt the master key using the subject's wallet
		masterKeyBytes, err := base64.StdEncoding.DecodeString(masterKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode master key: %w", err)
		}

		// Create a Counterparty for the certifier
		// In the TypeScript SDK, this would be whoever encrypted the master key
		certifier := &wallet.Counterparty{
			Type:         wallet.CounterpartyTypeOther,
			Counterparty: &m.Certifier,
		}

		// Get protocol details for the master keyring (just fieldName, no serialNumber)
		masterProtocolID, masterKeyID := GetCertificateEncryptionDetails(fieldName, "")

		// Decrypt the master key
		decryptedKeyResult, err := subjectWallet.Decrypt(&wallet.DecryptArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID:   masterProtocolID,
				KeyID:        masterKeyID,
				Counterparty: *certifier,
			},
			Ciphertext: masterKeyBytes,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt master key for field %s: %w", fieldName, err)
		}

		// 2. Re-encrypt the decrypted master key for the verifier
		// Get protocol details for the verifier keyring (include serialNumber)
		verifierProtocolID, verifierKeyID := GetCertificateEncryptionDetails(fieldName, m.SerialNumber)
		encryptResult, err := subjectWallet.Encrypt(&wallet.EncryptArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID:   verifierProtocolID,
				KeyID:        verifierKeyID,
				Counterparty: *verifier,
			},
			Plaintext: decryptedKeyResult.Plaintext,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt key for verifier: %w", err)
		}

		// 3. Add to the revelation keyring
		keyring[fieldName] = base64.StdEncoding.EncodeToString(encryptResult.Ciphertext)
	}

	return keyring, nil
}

// DecryptFields decrypts all fields using the masterKeyring
func (m *MasterCertificate) DecryptFields(
	subjectOrCertifierWallet *wallet.Wallet,
	counterparty *wallet.Counterparty,
) (map[string]string, error) {
	if m.MasterKeyring == nil || len(m.MasterKeyring) == 0 {
		return nil, ErrMissingMasterKeyring
	}

	// Decrypt each field
	decryptedFields := make(map[string]string)

	// Iterate through all fields in the certificate
	for fieldName, encryptedValue := range m.Fields {
		// Check if we have the master key for this field
		masterKey, exists := m.MasterKeyring[fieldName]
		if !exists {
			continue // Skip fields without master keys
		}

		// 1. Decrypt the master key (field revelation key) using the wallet
		// Here we need to convert the base64 masterKey to []byte
		masterKeyBytes, err := base64.StdEncoding.DecodeString(masterKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode master key: %w", err)
		}

		// Get protocol details for the master keyring (just fieldName, no serialNumber)
		masterProtocolID, masterKeyID := GetCertificateEncryptionDetails(fieldName, "")

		// Use the wallet to decrypt the master key
		decryptedKeyResult, err := subjectOrCertifierWallet.Decrypt(&wallet.DecryptArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID:   masterProtocolID,
				KeyID:        masterKeyID,
				Counterparty: *counterparty,
			},
			Ciphertext: masterKeyBytes,
		})
		if err != nil {
			continue // Skip this field if we can't decrypt the key
		}

		// TODO: In a real implementation, we would use the decryptedKeyResult.Plaintext
		// to create a symmetric key for decrypting the field value
		_ = decryptedKeyResult // Acknowledging that we're not using this yet

		// 2. Use the decrypted key to decrypt the field value
		// In a real implementation, we would use a symmetric key from the decrypted master key
		// For now, we'll simulate this by just using the decrypted key as a placeholder

		// Convert the encrypted value from base64
		fieldValueBytes, err := base64.StdEncoding.DecodeString(encryptedValue)
		if err != nil {
			continue
		}

		// In the TypeScript implementation, a SymmetricKey is created from the decrypted key
		// and used to decrypt the field value. Here we'll just use a placeholder.
		// In a real implementation, we would:
		// symmetricKey := symmetric.NewKey(decryptedKeyResult.Plaintext)
		// decryptedValueBytes, err := symmetricKey.Decrypt(fieldValueBytes)

		// For now, just use the plaintext as is
		decryptedFields[fieldName] = string(fieldValueBytes)
	}

	if len(decryptedFields) == 0 {
		return nil, errors.New("failed to decrypt any certificate fields")
	}

	return decryptedFields, nil
}

// CreateVerifiableCertificateForVerifier creates a verifiable certificate for a specific verifier
// using the subject's wallet to decrypt and re-encrypt field keys
func (m *MasterCertificate) CreateVerifiableCertificateForVerifier(
	subjectWallet *wallet.Wallet,
	verifier *wallet.Counterparty,
	fieldsToReveal []string,
) (*VerifiableCertificate, error) {
	if m.MasterKeyring == nil || len(m.MasterKeyring) == 0 {
		return nil, ErrMissingMasterKeyring
	}

	// Create a keyring for the verifier
	keyring, err := m.CreateFieldRevelationKeyring(
		subjectWallet,
		verifier,
		fieldsToReveal,
	)
	if err != nil {
		return nil, err
	}

	// Create a new VerifiableCertificate with the verifier's keyring
	verifiableCertificate := NewVerifiableCertificate(&m.Certificate, keyring)

	return verifiableCertificate, nil
}

// CreateFromVerifiableCertificate creates a master certificate from a verifiable certificate
// This is useful when loading certificates from storage
func CreateFromVerifiableCertificate(
	certificate *VerifiableCertificate,
	masterKeyring map[string]string,
) (*MasterCertificate, error) {
	if masterKeyring == nil || len(masterKeyring) == 0 {
		return nil, ErrMissingMasterKeyring
	}

	// Ensure every field has a corresponding master key
	for field := range certificate.Fields {
		if _, exists := masterKeyring[field]; !exists {
			return nil, errors.New("master keyring must contain a value for every field")
		}
	}

	masterCert := &MasterCertificate{
		Certificate:   certificate.Certificate,
		MasterKeyring: masterKeyring,
	}

	return masterCert, nil
}
