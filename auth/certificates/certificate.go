package certificates

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

var (
	ErrInvalidCertificate = errors.New("invalid-certificate")
	ErrAlreadySigned      = errors.New("certificate has already been signed")
)

// Certificate represents an Identity Certificate as per the Wallet interface specifications.
// It provides methods for serialization, deserialization, signing, and verifying certificates.
type Certificate struct {
	// Type identifier for the certificate, base64 encoded string, 32 bytes
	Type wallet.Base64String `json:"type"`

	// Unique serial number of the certificate, base64 encoded string, 32 bytes
	SerialNumber wallet.Base64String `json:"serialNumber"`

	// The public key belonging to the certificate's subject
	Subject ec.PublicKey `json:"subject"`

	// Public key of the certifier who issued the certificate
	Certifier ec.PublicKey `json:"certifier"`

	// The outpoint used to confirm that the certificate has not been revoked
	RevocationOutpoint *overlay.Outpoint `json:"revocationOutpoint"`

	// All the fields present in the certificate, with field names as keys and encrypted field values as strings
	Fields map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String `json:"fields"`

	// Certificate signature by the certifier's private key
	Signature []byte `json:"signature,omitempty"`
}

// NewCertificate creates a new certificate with the given fields
func NewCertificate(
	certType wallet.Base64String,
	serialNumber wallet.Base64String,
	subject ec.PublicKey,
	certifier ec.PublicKey,
	revocationOutpoint *overlay.Outpoint,
	fields map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String,
	signature []byte,
) *Certificate {
	return &Certificate{
		Type:               certType,
		SerialNumber:       serialNumber,
		Subject:            subject,
		Certifier:          certifier,
		RevocationOutpoint: revocationOutpoint,
		Fields:             fields,
		Signature:          signature,
	}
}

// ToBinary serializes the certificate into binary format
func (c *Certificate) ToBinary(includeSignature bool) ([]byte, error) {
	writer := util.NewWriter()

	// Write type (Base64String, 32 bytes)
	typeBytes, err := base64.StdEncoding.DecodeString(string(c.Type))
	if err != nil {
		return nil, fmt.Errorf("invalid type encoding: %w", err)
	}
	writer.WriteBytes(typeBytes)

	// Write serialNumber (Base64String, 32 bytes)
	serialNumberBytes, err := base64.StdEncoding.DecodeString(string(c.SerialNumber))
	if err != nil {
		return nil, fmt.Errorf("invalid serial number encoding: %w", err)
	}
	writer.WriteBytes(serialNumberBytes)

	// Write subject (33 bytes compressed public key)
	subjectBytes := c.Subject.Compressed()
	writer.WriteBytes(subjectBytes)

	// Write certifier (33 bytes compressed public key)
	certifierBytes := c.Certifier.Compressed()
	writer.WriteBytes(certifierBytes)

	// Write revocationOutpoint (TXID + OutputIndex)
	writer.WriteBytes(c.RevocationOutpoint.Txid[:])
	writer.WriteVarInt(uint64(c.RevocationOutpoint.OutputIndex))

	// Write fields
	// Sort field names lexicographically
	fieldNames := make([]wallet.CertificateFieldNameUnder50Bytes, 0, len(c.Fields))
	for fieldName := range c.Fields {
		fieldNames = append(fieldNames, fieldName)
	}
	sort.Slice(fieldNames, func(i, j int) bool {
		return fieldNames[i] < fieldNames[j]
	})

	// Write field count as varint
	writer.WriteVarInt(uint64(len(fieldNames)))

	for _, fieldName := range fieldNames {
		fieldValue := c.Fields[fieldName]

		// Field name length + name
		fieldNameBytes := []byte(fieldName)
		writer.WriteVarInt(uint64(len(fieldNameBytes)))
		writer.WriteBytes(fieldNameBytes)

		// Field value length + value
		fieldValueBytes := []byte(fieldValue)
		writer.WriteVarInt(uint64(len(fieldValueBytes)))
		writer.WriteBytes(fieldValueBytes)
	}

	// Write signature if included
	if includeSignature && len(c.Signature) > 0 {
		writer.WriteBytes(c.Signature)
	}

	return writer.Bytes(), nil
}

// CertificateFromBinary deserializes a certificate from binary format
func CertificateFromBinary(data []byte) (*Certificate, error) {
	reader := util.NewReader(data)

	// Read type (32 bytes)
	typeBytes, err := reader.ReadBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to read type: %w", err)
	}
	typeStr := base64.StdEncoding.EncodeToString(typeBytes)

	// Read serialNumber (32 bytes)
	serialNumberBytes, err := reader.ReadBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to read serial number: %w", err)
	}
	serialNumber := base64.StdEncoding.EncodeToString(serialNumberBytes)

	// Read subject (33 bytes)
	subjectBytes, err := reader.ReadBytes(33)
	if err != nil {
		return nil, fmt.Errorf("failed to read subject: %w", err)
	}
	subject, err := ec.ParsePubKey(subjectBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid subject public key: %w", err)
	}

	// Read certifier (33 bytes)
	certifierBytes, err := reader.ReadBytes(33)
	if err != nil {
		return nil, fmt.Errorf("failed to read certifier: %w", err)
	}
	certifier, err := ec.ParsePubKey(certifierBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid certifier public key: %w", err)
	}

	// Read revocationOutpoint
	txidBytes, err := reader.ReadBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to read txid: %w", err)
	}
	outputIndex, err := reader.ReadVarInt()
	if err != nil {
		return nil, fmt.Errorf("failed to read output index: %w", err)
	}

	// Create revocation outpoint
	revocationOutpoint := &overlay.Outpoint{
		Txid:        chainhash.Hash(txidBytes),
		OutputIndex: uint32(outputIndex),
	}

	// Read field count (varint)
	fieldCount, err := reader.ReadVarInt()
	if err != nil {
		return nil, fmt.Errorf("failed to read field count: %w", err)
	}

	// Read fields
	fields := make(map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String)
	for i := uint64(0); i < fieldCount; i++ {
		// Field name length (varint)
		fieldNameLength, err := reader.ReadVarInt()
		if err != nil {
			return nil, fmt.Errorf("failed to read field name length: %w", err)
		}

		// Field name
		fieldNameBytes, err := reader.ReadBytes(int(fieldNameLength))
		if err != nil {
			return nil, fmt.Errorf("failed to read field name: %w", err)
		}
		fieldName := wallet.CertificateFieldNameUnder50Bytes(string(fieldNameBytes))

		// Field value length (varint)
		fieldValueLength, err := reader.ReadVarInt()
		if err != nil {
			return nil, fmt.Errorf("failed to read field value length: %w", err)
		}

		// Field value
		fieldValueBytes, err := reader.ReadBytes(int(fieldValueLength))
		if err != nil {
			return nil, fmt.Errorf("failed to read field value: %w", err)
		}
		fieldValue := wallet.Base64String(string(fieldValueBytes))

		fields[fieldName] = fieldValue
	}

	// Read signature if present
	var signature []byte
	if !reader.EOF() {
		remaining, err := reader.Read()
		if err != nil {
			return nil, fmt.Errorf("failed to read signature: %w", err)
		}
		signature = remaining
	}

	return &Certificate{
		Type:               wallet.Base64String(typeStr),
		SerialNumber:       wallet.Base64String(serialNumber),
		Subject:            *subject,
		Certifier:          *certifier,
		RevocationOutpoint: revocationOutpoint,
		Fields:             fields,
		Signature:          signature,
	}, nil
}

// Verify checks the certificate's validity including signature verification
// A nil error response indicates a valid certificate
func (c *Certificate) Verify() error {
	// Verify the certificate signature
	if len(c.Signature) == 0 {
		// provide a fallback value (empty string)
		c.Signature = []byte("")
	}

	// Create a verifier wallet
	verifier, err := wallet.NewProtoWallet(nil)
	if err != nil {
		return fmt.Errorf("failed to create verifier wallet: %w", err)
	}

	// Get the binary representation without the signature
	data, err := c.ToBinary(false)
	if err != nil {
		return fmt.Errorf("failed to serialize certificate: %w", err)
	}

	// Parse the signature
	sig, err := ec.ParseSignature(c.Signature)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %w", err)
	}

	// Verify the signature using the certifier's public key
	verifyArgs := &wallet.VerifySignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "certificate signature",
			},
			KeyID: fmt.Sprintf("%s %s", c.Type, c.SerialNumber),
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: &c.Certifier,
			},
		},
		Data:      data,
		Signature: *sig,
	}

	verifyResult, err := verifier.VerifySignature(verifyArgs)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	if !verifyResult.Valid {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

// Sign adds a signature to the certificate using the certifier's wallet
// Certificate must not be already signed.
func (c *Certificate) Sign(certifierWallet wallet.ProtoWallet) error {
	if c.Signature != nil && len(c.Signature) > 0 {
		return ErrAlreadySigned
	}

	// Get the wallet's identity public key and update the certificate's certifier field
	pubKeyResult, err := certifierWallet.GetPublicKey(&wallet.GetPublicKeyArgs{
		IdentityKey: true,
	})
	if err != nil {
		return fmt.Errorf("failed to get wallet identity key: %w", err)
	}
	c.Certifier = *pubKeyResult

	// Prepare for signing - exclude the signature when signing
	dataToSign, err := c.ToBinary(false)
	if err != nil {
		return fmt.Errorf("failed to serialize certificate: %w", err)
	}

	// Create signature with the certifier's wallet
	signArgs := &wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "certificate signature",
			},
			KeyID: fmt.Sprintf("%s %s", c.Type, c.SerialNumber),
			Counterparty: wallet.Counterparty{
				Type: wallet.CounterpartyTypeAnyone,
			},
		},
		Data: dataToSign,
	}

	// Create signature
	signResult, err := certifierWallet.CreateSignature(signArgs, "go-sdk")
	if err != nil {
		return fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Store the signature
	c.Signature = signResult.Signature.Serialize()

	return nil
}

// GetCertificateEncryptionDetails returns protocol ID and key ID for certificate field encryption
// For master certificate creation, no serial number is provided because entropy is required
// from both the client and the certifier. In this case, the keyID is simply the fieldName.
// For VerifiableCertificates verifier keyring creation, both the serial number and field name are available,
// so the keyID is formed by concatenating the serialNumber and fieldName.
func GetCertificateEncryptionDetails(fieldName string, serialNumber string) (wallet.Protocol, string) {
	protocolID := wallet.Protocol{
		SecurityLevel: wallet.SecurityLevelEveryApp,
		Protocol:      "certificate field encryption",
	}

	var keyID string
	if serialNumber != "" {
		keyID = serialNumber + " " + fieldName
	} else {
		keyID = fieldName
	}

	return protocolID, keyID
}
