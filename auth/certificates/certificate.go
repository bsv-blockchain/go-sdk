package certificates

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/bsv-blockchain/go-sdk/overlay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
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
	Type string `json:"type"`

	// Unique serial number of the certificate, base64 encoded string, 32 bytes
	SerialNumber string `json:"serialNumber"`

	// The public key belonging to the certificate's subject
	Subject ec.PublicKey `json:"subject"`

	// Public key of the certifier who issued the certificate
	Certifier ec.PublicKey `json:"certifier"`

	// The outpoint used to confirm that the certificate has not been revoked
	RevocationOutpoint *overlay.Outpoint `json:"revocationOutpoint"`

	// All the fields present in the certificate, with field names as keys and encrypted field values as strings
	Fields map[string]string `json:"fields"`

	// Certificate signature by the certifier's private key
	Signature []byte `json:"signature,omitempty"`
}

// NewCertificate creates a new certificate with the given fields
func NewCertificate(
	certType string,
	serialNumber string,
	subject ec.PublicKey,
	certifier ec.PublicKey,
	revocationOutpoint *overlay.Outpoint,
	fields map[string]string,
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
	// Create a buffer to hold the binary data
	var buffer []byte

	// Write type (Base64String, 32 bytes)
	typeBytes, err := base64.StdEncoding.DecodeString(c.Type)
	if err != nil {
		return nil, fmt.Errorf("invalid type encoding: %w", err)
	}
	buffer = append(buffer, typeBytes...)

	// Write serialNumber (Base64String, 32 bytes)
	serialNumberBytes, err := base64.StdEncoding.DecodeString(c.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("invalid serial number encoding: %w", err)
	}
	buffer = append(buffer, serialNumberBytes...)

	// Write subject (33 bytes compressed public key)
	subjectBytes := c.Subject.Compressed()
	buffer = append(buffer, subjectBytes...)

	// Write certifier (33 bytes compressed public key)
	certifierBytes := c.Certifier.Compressed()
	buffer = append(buffer, certifierBytes...)

	// Write revocationOutpoint (TXID + OutputIndex)
	if c.RevocationOutpoint != nil {
		// In Go SDK, the overlay.Outpoint.Txid is already a byte array, so we can use it directly
		buffer = append(buffer, c.RevocationOutpoint.Txid[:]...)

		// Write output index as varint
		outputIndex := c.RevocationOutpoint.OutputIndex
		varIntBytes := writeVarInt(uint64(outputIndex))
		buffer = append(buffer, varIntBytes...)
	} else {
		// Default empty outpoint (32 bytes of zeros + varint 0)
		buffer = append(buffer, make([]byte, 32)...)
		buffer = append(buffer, 0) // varint 0
	}

	// Write fields
	// Sort field names lexicographically
	fieldNames := make([]string, 0, len(c.Fields))
	for fieldName := range c.Fields {
		fieldNames = append(fieldNames, fieldName)
	}
	sort.Strings(fieldNames)

	// Write field count as varint
	varIntBytes := writeVarInt(uint64(len(fieldNames)))
	buffer = append(buffer, varIntBytes...)

	// Write each field
	for _, fieldName := range fieldNames {
		fieldValue := c.Fields[fieldName]

		// Field name length + name
		fieldNameBytes := []byte(fieldName)
		fieldNameLenBytes := writeVarInt(uint64(len(fieldNameBytes)))
		buffer = append(buffer, fieldNameLenBytes...)
		buffer = append(buffer, fieldNameBytes...)

		// Field value length + value
		fieldValueBytes := []byte(fieldValue)
		fieldValueLenBytes := writeVarInt(uint64(len(fieldValueBytes)))
		buffer = append(buffer, fieldValueLenBytes...)
		buffer = append(buffer, fieldValueBytes...)
	}

	// Write signature if included
	if includeSignature && len(c.Signature) > 0 {
		buffer = append(buffer, c.Signature...)
	}

	return buffer, nil
}

// CertificateFromBinary deserializes a certificate from binary format
func CertificateFromBinary(data []byte) (*Certificate, error) {
	if len(data) < 130 { // Minimum size for basic fields
		return nil, ErrInvalidCertificate
	}

	offset := 0

	// Read type (32 bytes)
	typeBytes := data[offset : offset+32]
	typeStr := base64.StdEncoding.EncodeToString(typeBytes)
	offset += 32

	// Read serialNumber (32 bytes)
	serialNumberBytes := data[offset : offset+32]
	serialNumber := base64.StdEncoding.EncodeToString(serialNumberBytes)
	offset += 32

	// Read subject (33 bytes)
	subjectBytes := data[offset : offset+33]
	subject, err := ec.ParsePubKey(subjectBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid subject public key: %w", err)
	}
	offset += 33

	// Read certifier (33 bytes)
	certifierBytes := data[offset : offset+33]
	certifier, err := ec.ParsePubKey(certifierBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid certifier public key: %w", err)
	}
	offset += 33

	// Read revocationOutpoint
	txidBytes := data[offset : offset+32]
	offset += 32

	// Read output index (varint)
	outputIndex, bytesRead := readVarInt(data[offset:])
	offset += bytesRead

	// Create revocation outpoint
	revocationOutpoint := &overlay.Outpoint{
		OutputIndex: uint32(outputIndex),
	}
	// Copy txid bytes into the Hash field
	copy(revocationOutpoint.Txid[:], txidBytes)

	// Read field count (varint)
	fieldCount, bytesRead := readVarInt(data[offset:])
	offset += bytesRead

	// Read fields
	fields := make(map[string]string)
	for i := uint64(0); i < fieldCount; i++ {
		// Read field name length (varint)
		fieldNameLen, bytesRead := readVarInt(data[offset:])
		offset += bytesRead

		// Read field name
		fieldName := string(data[offset : offset+int(fieldNameLen)])
		offset += int(fieldNameLen)

		// Read field value length (varint)
		fieldValueLen, bytesRead := readVarInt(data[offset:])
		offset += bytesRead

		// Read field value
		fieldValue := string(data[offset : offset+int(fieldValueLen)])
		offset += int(fieldValueLen)

		fields[fieldName] = fieldValue
	}

	// Read signature if present
	var signature []byte
	if offset < len(data) {
		signature = data[offset:]
	}

	// Create certificate
	cert := &Certificate{
		Type:               typeStr,
		SerialNumber:       serialNumber,
		Subject:            *subject,
		Certifier:          *certifier,
		RevocationOutpoint: revocationOutpoint,
		Fields:             fields,
		Signature:          signature,
	}

	return cert, nil
}

// Verify checks the certificate's validity including signature verification
func (c *Certificate) Verify() error {
	// Verify the certificate signature
	if len(c.Signature) == 0 {
		return fmt.Errorf("certificate has no signature")
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
	valid := c.Certifier.Verify(data, sig)
	if !valid {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

// Sign adds a signature to the certificate using the certifier's wallet
// Certificate must not be already signed
func (c *Certificate) Sign(certifierWallet *wallet.Wallet) error {
	if c.Signature != nil && len(c.Signature) > 0 {
		return ErrAlreadySigned
	}

	// Prepare for signing
	dataToSign, err := c.ToBinary(false)
	if err != nil {
		return fmt.Errorf("failed to serialize certificate: %w", err)
	}

	// Create signature with the certifier's wallet
	signArgs := &wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "Certificate",
			},
			KeyID: c.SerialNumber,
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
	// The TypeScript SDK uses the DER encoded signature + 1 byte for recoveryId
	c.Signature = signResult.Signature.Serialize()

	return nil
}

// GetCertificateEncryptionDetails returns protocol ID and key ID for certificate field encryption
func GetCertificateEncryptionDetails(fieldName string, serialNumber string) (wallet.Protocol, string) {
	return wallet.Protocol{
			SecurityLevel: wallet.SecurityLevelEveryApp,
			Protocol:      "certificate field encryption",
		}, func() string {
			if serialNumber != "" {
				return serialNumber + " " + fieldName
			}
			return fieldName
		}()
}

// Helper functions for varint encoding/decoding
func writeVarInt(value uint64) []byte {
	if value < 0xfd {
		return []byte{byte(value)}
	} else if value <= 0xffff {
		buf := make([]byte, 3)
		buf[0] = 0xfd
		binary.LittleEndian.PutUint16(buf[1:], uint16(value))
		return buf
	} else if value <= 0xffffffff {
		buf := make([]byte, 5)
		buf[0] = 0xfe
		binary.LittleEndian.PutUint32(buf[1:], uint32(value))
		return buf
	} else {
		buf := make([]byte, 9)
		buf[0] = 0xff
		binary.LittleEndian.PutUint64(buf[1:], value)
		return buf
	}
}

func readVarInt(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}

	switch data[0] {
	case 0xfd:
		if len(data) < 3 {
			return 0, 1
		}
		return uint64(binary.LittleEndian.Uint16(data[1:3])), 3
	case 0xfe:
		if len(data) < 5 {
			return 0, 1
		}
		return uint64(binary.LittleEndian.Uint32(data[1:5])), 5
	case 0xff:
		if len(data) < 9 {
			return 0, 1
		}
		return binary.LittleEndian.Uint64(data[1:9]), 9
	default:
		return uint64(data[0]), 1
	}
}
