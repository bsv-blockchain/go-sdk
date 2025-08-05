package certificates

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

var (
	ErrInvalidMasterCertificate = errors.New("invalid master certificate")
	ErrMissingMasterKeyring     = errors.New("master keyring is required")
	ErrFieldNotFound            = errors.New("field not found")
	ErrKeyNotFoundInKeyring     = errors.New("key not found in keyring")
	ErrDecryptionFailed         = errors.New("decryption failed")
	ErrEncryptionFailed         = errors.New("encryption failed")
)

// MasterCertificate extends the Certificate struct to include a master keyring
// for key management and selective disclosure of certificate fields.
// It mirrors the structure and functionality of the MasterCertificate class in the TypeScript SDK.
type MasterCertificate struct {
	// Embed the base Certificate struct
	Certificate
	// MasterKeyring contains encrypted symmetric keys (Base64 encoded) for each field.
	// The key is the field name, and the value is the encrypted key.
	MasterKeyring map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64 `json:"masterKeyring,omitempty"`
}

// NewMasterCertificate creates a new MasterCertificate instance.
// It validates that the masterKeyring contains an entry for every field in the base certificate.
func NewMasterCertificate(
	cert *Certificate,
	masterKeyring map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64,
) (*MasterCertificate, error) {
	if len(masterKeyring) == 0 {
		return nil, ErrMissingMasterKeyring
	}

	// Ensure every field in `cert.Fields` has a corresponding key in `masterKeyring`
	for fieldName := range cert.Fields {
		if _, exists := masterKeyring[fieldName]; !exists {
			return nil, fmt.Errorf("master keyring must contain a value for every field. Missing key for field: %s", fieldName)
		}
	}

	masterCert := &MasterCertificate{
		Certificate:   *cert,
		MasterKeyring: masterKeyring,
	}

	return masterCert, nil
}

// CertificateFieldsResult holds the results from creating encrypted certificate fields.
type CertificateFieldsResult struct {
	CertificateFields map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64
	MasterKeyring     map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64
}

// CreateCertificateFields encrypts certificate fields for a subject and generates a master keyring.
// This static method mirrors the TypeScript implementation.
func CreateCertificateFields(
	ctx context.Context,
	creatorWallet wallet.CipherOperations,
	certifierOrSubject wallet.Counterparty,
	fields map[wallet.CertificateFieldNameUnder50Bytes]string, // Plaintext field values
	privileged bool,
	privilegedReason string,
) (*CertificateFieldsResult, error) {
	certificateFields := make(map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64)
	masterKeyring := make(map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64)

	for fieldName, fieldValue := range fields {
		// 1. Generate a random symmetric key (32 bytes)
		fieldSymmetricKeyBytes := make([]byte, 32)
		if _, err := rand.Read(fieldSymmetricKeyBytes); err != nil {
			return nil, fmt.Errorf("failed to generate random key for field %s: %w", fieldName, err)
		}
		fieldSymmetricKey := ec.NewSymmetricKey(fieldSymmetricKeyBytes)

		// 2. Encrypt the field value with this key
		encryptedFieldValue, err := fieldSymmetricKey.Encrypt([]byte(fieldValue))
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt field value for %s: %w", fieldName, err)
		}
		certificateFields[fieldName] = wallet.StringBase64(base64.StdEncoding.EncodeToString(encryptedFieldValue))

		// 3. Encrypt the symmetric key for the certifier/subject
		protocolID, keyID := GetCertificateEncryptionDetails(string(fieldName), "") // No serial number for master keyring creation
		encryptedKey, err := creatorWallet.Encrypt(ctx, wallet.EncryptArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID:       protocolID,
				KeyID:            keyID,
				Counterparty:     certifierOrSubject,
				Privileged:       privileged,
				PrivilegedReason: privilegedReason,
			},
			Plaintext: fieldSymmetricKeyBytes,
		}, "")
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt field revelation key for %s: %w", fieldName, err)
		}
		masterKeyring[fieldName] = wallet.StringBase64(base64.StdEncoding.EncodeToString(encryptedKey.Ciphertext))
	}

	return &CertificateFieldsResult{
		CertificateFields: certificateFields,
		MasterKeyring:     masterKeyring,
	}, nil
}

type CertifierWallet interface {
	wallet.PublicKeyGetter
	wallet.CipherOperations
	wallet.SignatureOperations
}

// IssueCertificateForSubject creates a new MasterCertificate for a specified subject.
// This method generates a certificate containing encrypted fields and a keyring
// for the subject to decrypt all fields. Each field is encrypted with a randomly
// generated symmetric key, which is then encrypted for the subject. The certificate
// can also include a revocation outpoint to manage potential revocation.
// This static method mirrors the TypeScript implementation.
func IssueCertificateForSubject(
	ctx context.Context,
	certifierWallet CertifierWallet,
	subject wallet.Counterparty,
	plainFields map[string]string, // Plaintext fields
	certificateType string,
	getRevocationOutpoint func(string) (*transaction.Outpoint, error), // Optional func
	serialNumberStr string, // Optional serial number as StringBase64
) (*MasterCertificate, error) {

	// 1. Generate a random serialNumber if not provided
	var serialNumber wallet.StringBase64
	if serialNumberStr != "" {
		serialNumber = wallet.StringBase64(serialNumberStr)
	} else {
		serialBytes := make([]byte, 32)
		if _, err := rand.Read(serialBytes); err != nil {
			return nil, fmt.Errorf("failed to generate random serial number: %w", err)
		}
		serialNumber = wallet.StringBase64(base64.StdEncoding.EncodeToString(serialBytes))
	}

	// Convert plainFields map[string]string to map[wallet.CertificateFieldNameUnder50Bytes]string
	fieldsForEncryption := make(map[wallet.CertificateFieldNameUnder50Bytes]string)
	for k, v := range plainFields {
		// Validate that field name is under 50 bytes
		if len(k) > 50 {
			return nil, fmt.Errorf("certificate field name '%s' exceeds 50 bytes limit (%d bytes)", k, len(k))
		}
		fieldsForEncryption[wallet.CertificateFieldNameUnder50Bytes(k)] = v
	}

	// 2. Create encrypted certificate fields and associated master keyring
	fieldResult, err := CreateCertificateFields(ctx, certifierWallet, subject, fieldsForEncryption, false, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate fields: %w", err)
	}

	// 3. Get the identity public key of the certifier
	certifierPubKey, err := certifierWallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get certifier public key: %w", err)
	}

	// Check if the obtained public key is valid internally
	if certifierPubKey == nil || certifierPubKey.PublicKey.X == nil {
		return nil, errors.New("failed to get a valid certifier public key from wallet")
	}

	// 4. Get revocation outpoint
	var revocationOutpoint *transaction.Outpoint
	if getRevocationOutpoint != nil {
		revocationOutpoint, err = getRevocationOutpoint(string(serialNumber))
		if err != nil {
			return nil, fmt.Errorf("failed to get revocation outpoint: %w", err)
		}
	} else {
		// Default to empty outpoint (matching TS behavior where undefined becomes empty string)
		revocationOutpoint = &transaction.Outpoint{} // Assuming empty TXID and index 0 is the placeholder
	}

	// 5. Create the base Certificate struct
	baseCert := &Certificate{
		Type:               wallet.StringBase64(certificateType),
		SerialNumber:       serialNumber,
		Certifier:          *certifierPubKey.PublicKey,
		RevocationOutpoint: revocationOutpoint,
		Fields:             fieldResult.CertificateFields,
	}

	// Set the Subject field based on counterparty type
	switch subject.Type {
	case wallet.CounterpartyTypeSelf:
		// For self-signed certs, use the certifier's identity key as the subject
		baseCert.Subject = *certifierPubKey.PublicKey
	case wallet.CounterpartyTypeOther:
		// For other-signed certs, ensure the counterparty has a public key
		if subject.Counterparty == nil {
			return nil, fmt.Errorf("subject counterparty is TypeOther but has a nil public key")
		}
		baseCert.Subject = *subject.Counterparty
	case wallet.CounterpartyTypeAnyone:
		// For "anyone" counterparty, use the certifier's key as well
		baseCert.Subject = *certifierPubKey.PublicKey
	default:
		return nil, fmt.Errorf("unhandled subject counterparty type: %v", subject.Type)
	}

	// 6. Create the MasterCertificate instance
	masterCert, err := NewMasterCertificate(baseCert, fieldResult.MasterKeyring)
	if err != nil {
		return nil, fmt.Errorf("failed to create master certificate instance: %w", err)
	}

	// 7. Sign the certificate
	err = masterCert.Sign(ctx, certifierWallet)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	return masterCert, nil
}

// DecryptFieldResult holds the results from decrypting a single certificate field.
type DecryptFieldResult struct {
	FieldRevelationKey  []byte // The decrypted symmetric key for the field
	DecryptedFieldValue string // The plaintext field value
}

// DecryptField decrypts a single field using the master keyring.
// This static method mirrors the TypeScript implementation.
func DecryptField(
	ctx context.Context,
	subjectOrCertifierWallet wallet.CipherOperations,
	masterKeyring map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64,
	fieldName wallet.CertificateFieldNameUnder50Bytes,
	encryptedFieldValue wallet.StringBase64, // Base64 encoded encrypted value
	counterparty wallet.Counterparty,
	privileged bool,
	privilegedReason string,
) (*DecryptFieldResult, error) {
	if len(masterKeyring) == 0 {
		return nil, ErrMissingMasterKeyring
	}

	// 1. Get the encrypted field revelation key from the master keyring
	encryptedKeyBase64, exists := masterKeyring[fieldName]
	if !exists {
		return nil, fmt.Errorf("%w: field %s", ErrKeyNotFoundInKeyring, fieldName)
	}
	encryptedKeyBytes, err := base64.StdEncoding.DecodeString(string(encryptedKeyBase64))
	if err != nil {
		return nil, fmt.Errorf("failed to decode master key for field %s: %w", fieldName, err)
	}

	// 2. Decrypt the field revelation key
	protocolID, keyID := GetCertificateEncryptionDetails(string(fieldName), "") // No serial number
	decryptedBytes, err := subjectOrCertifierWallet.Decrypt(ctx, wallet.DecryptArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID:       protocolID,
			KeyID:            keyID,
			Counterparty:     counterparty,
			Privileged:       privileged,
			PrivilegedReason: privilegedReason,
		},
		Ciphertext: encryptedKeyBytes,
	}, "")
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt field revelation key for %s: %w", fieldName, err)
	}
	fieldRevelationKey := decryptedBytes.Plaintext

	// 3. Decrypt the field value using the field revelation key
	encryptedFieldBytes, err := base64.StdEncoding.DecodeString(string(encryptedFieldValue))
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted field value for %s: %w", fieldName, err)
	}

	// Use the field revelation key as a symmetric key
	symmetricKey := ec.NewSymmetricKey(fieldRevelationKey)
	plaintextFieldBytes, err := symmetricKey.Decrypt(encryptedFieldBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt field %s value: %w", fieldName, ErrDecryptionFailed)
	}

	return &DecryptFieldResult{
		FieldRevelationKey:  fieldRevelationKey,
		DecryptedFieldValue: string(plaintextFieldBytes),
	}, nil
}

// DecryptFields decrypts multiple fields using the master keyring.
// This static method mirrors the TypeScript implementation.
func DecryptFields(
	ctx context.Context,
	subjectOrCertifierWallet wallet.CipherOperations,
	masterKeyring map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64,
	fields map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64, // Encrypted fields
	counterparty wallet.Counterparty,
	privileged bool,
	privilegedReason string,
) (map[wallet.CertificateFieldNameUnder50Bytes]string, error) { // Returns map of plaintext values
	if len(masterKeyring) == 0 {
		return nil, ErrMissingMasterKeyring
	}
	if fields == nil {
		return nil, errors.New("fields map cannot be nil")
	}

	decryptedFields := make(map[wallet.CertificateFieldNameUnder50Bytes]string)

	for fieldName, encryptedFieldValue := range fields {
		result, err := DecryptField(
			ctx,
			subjectOrCertifierWallet,
			masterKeyring,
			fieldName,
			encryptedFieldValue,
			counterparty,
			privileged,
			privilegedReason,
		)
		if err != nil {
			// If any field fails, the whole operation fails
			return nil, fmt.Errorf("failed to decrypt field %s: %w", fieldName, err)
		}
		decryptedFields[fieldName] = result.DecryptedFieldValue
	}

	return decryptedFields, nil
}

// CreateKeyringForVerifier creates a keyring for a verifier that allows them to decrypt specific fields
// in a certificate. The subject decrypts the master key, then re-encrypts it for the verifier.
// This allows selective disclosure of certificate fields to specific verifiers.
// This static method mirrors the TypeScript implementation.
func CreateKeyringForVerifier(
	ctx context.Context,
	subjectWallet wallet.CipherOperations,
	certifier wallet.Counterparty, // Counterparty used when decrypting master key
	verifier wallet.Counterparty, // Counterparty to encrypt for
	fields map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64, // All encrypted fields from cert
	fieldsToReveal []wallet.CertificateFieldNameUnder50Bytes, // Which fields to include in the new keyring
	masterKeyring map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64, // The original master keyring
	serialNumber wallet.StringBase64, // Serial number needed for encryption protocol/key ID
	privileged bool,
	privilegedReason string,
) (map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64, error) { // Returns the verifier-specific keyring
	if len(masterKeyring) == 0 {
		return nil, ErrMissingMasterKeyring
	}

	// Create a new verifier-specific keyring
	keyringForVerifier := make(map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64)

	// For each field to reveal:
	for _, fieldName := range fieldsToReveal {
		// Check if the field exists in the certificate
		if _, exists := fields[fieldName]; !exists {
			return nil, fmt.Errorf("%w for field %s", ErrFieldNotFound, fieldName)
		}

		// First decrypt the master key
		decryptedKey, err := DecryptField(
			ctx,
			subjectWallet,
			masterKeyring,
			fieldName,
			fields[fieldName],
			certifier,
			privileged,
			privilegedReason,
		)
		if err != nil {
			// Wrap the original error with our ErrDecryptionFailed
			return nil, fmt.Errorf("failed to decrypt master key for field %s during keyring creation: %w: %v",
				fieldName, ErrDecryptionFailed, err)
		}
		fieldRevelationKey := decryptedKey.FieldRevelationKey

		// 2. Re-encrypt the field revelation key for the verifier
		protocolID, keyID := GetCertificateEncryptionDetails(string(fieldName), string(serialNumber))
		encryptedKeyForVerifier, err := subjectWallet.Encrypt(ctx, wallet.EncryptArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID:       protocolID,
				KeyID:            keyID,
				Counterparty:     verifier,
				Privileged:       privileged,
				PrivilegedReason: privilegedReason,
			},
			Plaintext: fieldRevelationKey,
		}, "")
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt field key for verifier: %w", err)
		}

		// 3. Store in verifier keyring
		keyringForVerifier[fieldName] = wallet.StringBase64(base64.StdEncoding.EncodeToString(encryptedKeyForVerifier.Ciphertext))
	}

	return keyringForVerifier, nil
}

// Note: Methods like `createVerifiableCertificate` would typically belong in a
// separate `VerifiableCertificate` struct/file, which would use the methods
// defined here (like `CreateKeyringForVerifier`). This file focuses only on
// implementing the `MasterCertificate` structure and its associated static methods
// as defined in the TypeScript `MasterCertificate.ts`.
