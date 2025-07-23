package certificates

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// VerifiableCertificate extends the Certificate struct to include a verifier-specific keyring.
// This keyring allows selective decryption of certificate fields for authorized verifiers.
// It mirrors the structure and functionality of the TypeScript VerifiableCertificate class.
type VerifiableCertificate struct {
	// Embed the base Certificate struct. Fields like Type, SerialNumber, Subject,
	// Certifier, RevocationOutpoint, Fields, and Signature are inherited.
	Certificate

	// KeyRing contains the encrypted field revelation keys, specifically encrypted for the intended verifier.
	// The map keys are the field names (string), and values are the base64 encoded encrypted keys (string).
	Keyring map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64 `json:"keyring,omitempty"`

	// DecryptedFields stores the successfully decrypted field values after calling DecryptFields.
	// Populated only upon successful decryption of all fields present in the KeyRing.
	// The map keys are the field names (string), and values are the decrypted plaintext field values (string).
	DecryptedFields map[string]string `json:"decryptedFields,omitempty"`
}

// NewVerifiableCertificate creates a new VerifiableCertificate instance.
// It takes a pointer to a base Certificate and the verifier-specific KeyRing.
func NewVerifiableCertificate(
	cert *Certificate, // Pointer to the base Certificate data
	keyring map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64, // Verifier-specific keyring
) *VerifiableCertificate {
	return &VerifiableCertificate{
		Certificate: *cert, // Dereference and copy the base certificate data
		Keyring:     keyring,
		// DecryptedFields is initialized implicitly as a nil map
	}
}

// NewVerifiableCertificateFromBinary deserializes a certificate from binary format into a VerifiableCertificate
func NewVerifiableCertificateFromBinary(data []byte) (*VerifiableCertificate, error) {
	// First deserialize into a base Certificate
	cert, err := CertificateFromBinary(data)
	if err != nil {
		return nil, err
	}

	// Create a VerifiableCertificate with an empty keyring
	verifiableCert := &VerifiableCertificate{
		Certificate:     *cert,
		Keyring:         make(map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64),
		DecryptedFields: make(map[string]string),
	}

	return verifiableCert, nil
}

// DecryptFields decrypts selectively revealed certificate fields using the provided keyring and verifier wallet.
// This method mirrors the decryptFields method in the TypeScript implementation.
//
// Args:
//
//	verifierWallet: The wallet instance of the certificate's verifier (must implement wallet.Interface).
//	                Used to decrypt the field revelation keys stored in the KeyRing.
//	privileged:     Whether this is a privileged request (optional, defaults to false).
//	privilegedReason: Reason provided for privileged access (optional, required if privileged is true).
//
// Returns:
//
//	A map[string]string containing the decrypted field names and their plaintext values.
//	An error if the keyring is missing/empty or if any decryption operation fails.
func (vc *VerifiableCertificate) DecryptFields(
	ctx context.Context,
	verifierWallet wallet.Interface, // Use the interface type
	privileged bool,
	privilegedReason string,
) (map[string]string, error) {
	// Check if the KeyRing is nil or empty
	if len(vc.Keyring) == 0 {
		return nil, errors.New("a keyring is required to decrypt certificate fields for the verifier")
	}

	// Initialize the map to store results.
	decryptedFields := make(map[string]string)

	// The counterparty for decrypting the field revelation keys is the Subject of the certificate.
	// Check if the Subject field is initialized before using it
	subjectKey := vc.Subject
	if subjectKey.X == nil || subjectKey.Y == nil {
		return nil, errors.New("certificate subject is invalid or not initialized")
	}

	subjectCounterparty := wallet.Counterparty{
		Type:         wallet.CounterpartyTypeOther,
		Counterparty: &subjectKey, // Use the Subject from the embedded Certificate
	}

	// Iterate through the fields specified in the verifier's KeyRing.
	for fieldName, encryptedKeyBase64 := range vc.Keyring {
		// 1. Decrypt the field revelation key using the verifier's wallet.
		encryptedKeyBytes, err := base64.StdEncoding.DecodeString(string(encryptedKeyBase64))
		if err != nil {
			// Wrap error to provide context, matching TS error style
			return nil, fmt.Errorf("failed to decrypt selectively revealed certificate fields using keyring: failed to decode base64 key for field '%s': %w", fieldName, err)
		}

		// Get encryption details (ProtocolID and KeyID) for this specific field.
		// Use the certificate's serial number as required for verifier keyring decryption.
		protocolID, keyID := GetCertificateEncryptionDetails(string(fieldName), string(vc.SerialNumber))

		decryptResult, err := verifierWallet.Decrypt(ctx, wallet.DecryptArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID:       protocolID,
				KeyID:            keyID,
				Counterparty:     subjectCounterparty,
				Privileged:       privileged,
				PrivilegedReason: privilegedReason,
			},
			Ciphertext: encryptedKeyBytes,
		}, "")
		if err != nil {
			// Wrap error from the wallet's Decrypt method, matching TS error style
			return nil, fmt.Errorf("failed to decrypt selectively revealed certificate fields using keyring: wallet decryption failed for field '%s': %w", fieldName, err)
		}
		if decryptResult == nil {
			return nil, fmt.Errorf("failed to decrypt selectively revealed certificate fields using keyring: wallet decryption returned nil for field '%s'", fieldName)
		}
		fieldRevelationKey := decryptResult.Plaintext

		// 2. Decrypt the actual field value using the field revelation key.
		encryptedFieldValueBase64, exists := vc.Fields[fieldName]
		if !exists {
			// This case should ideally not happen if the keyring is consistent with fields,
			// but handle it defensively.
			return nil, fmt.Errorf("failed to decrypt selectively revealed certificate fields using keyring: field '%s' not found in certificate fields", fieldName)
		}
		encryptedFieldValueBytes, err := base64.StdEncoding.DecodeString(string(encryptedFieldValueBase64))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt selectively revealed certificate fields using keyring: failed to decode base64 field value for '%s': %w", fieldName, err)
		}

		symmetricKey := primitives.NewSymmetricKey(fieldRevelationKey)
		decryptedFieldBytes, err := symmetricKey.Decrypt(encryptedFieldValueBytes)
		if err != nil {
			// Wrap error from symmetric decryption, matching TS error style
			return nil, fmt.Errorf("failed to decrypt selectively revealed certificate fields using keyring: symmetric decryption failed for field '%s': %w", fieldName, err)
		}

		// Store the successfully decrypted plaintext value.
		decryptedFields[string(fieldName)] = string(decryptedFieldBytes)
	}

	// If all fields in the keyring were decrypted successfully, store the result and return.
	vc.DecryptedFields = decryptedFields
	return decryptedFields, nil
}
