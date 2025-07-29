// Package certificates implements a certificate-based authentication system for the BSV blockchain.
// It provides structures and methods for creating, validating, and managing both master certificates
// (which establish identity) and verifiable certificates (which grant specific permissions).
// Certificates support field encryption/decryption, signature verification, and integration with
// the wallet system for cryptographic operations.
package certificates

import (
	"context"
	"errors"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/serializer"
)

var (
	ErrInvalidCertificate = errors.New("invalid-certificate")
	ErrAlreadySigned      = errors.New("certificate has already been signed")
	ErrNotSigned          = errors.New("certificate is not signed")
)

// Certificate represents an Identity Certificate as per the Wallet interface specifications.
// It provides methods for serialization, deserialization, signing, and verifying certificates.
type Certificate struct {
	// Type identifier for the certificate, base64 encoded string, 32 bytes
	Type wallet.StringBase64 `json:"type"`

	// Unique serial number of the certificate, base64 encoded string, 32 bytes
	SerialNumber wallet.StringBase64 `json:"serialNumber"`

	// The public key belonging to the certificate's subject
	Subject ec.PublicKey `json:"subject"`

	// Public key of the certifier who issued the certificate
	Certifier ec.PublicKey `json:"certifier"`

	// The outpoint used to confirm that the certificate has not been revoked
	RevocationOutpoint *transaction.Outpoint `json:"revocationOutpoint"`

	// All the fields present in the certificate, with field names as keys and encrypted field values as strings
	Fields map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64 `json:"fields"`

	// Certificate signature by the certifier's private key
	Signature []byte `json:"signature,omitempty"`
}

// NewCertificate creates a new certificate with the given fields
func NewCertificate(
	certType wallet.StringBase64,
	serialNumber wallet.StringBase64,
	subject ec.PublicKey,
	certifier ec.PublicKey,
	revocationOutpoint *transaction.Outpoint,
	fields map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64,
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
	walletCert, err := c.ToWalletCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to convert certificate to wallet format: %w", err)
	}

	var data []byte
	if includeSignature {
		data, err = serializer.SerializeCertificate(walletCert)
	} else {
		data, err = serializer.SerializeCertificateNoSignature(walletCert)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to serialize certificate: %w", err)
	}

	return data, nil
}

// CertificateFromBinary deserializes a certificate from binary format
func CertificateFromBinary(data []byte) (*Certificate, error) {
	walletCert, err := serializer.DeserializeCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize certificate: %w", err)
	}

	cert, err := FromWalletCertificate(walletCert)
	if err != nil {
		return nil, fmt.Errorf("failed to convert wallet certificate to Certificate: %w", err)
	}

	return cert, nil
}

// Verify checks the certificate's validity including signature verification
// A nil error response indicates a valid certificate
func (c *Certificate) Verify(ctx context.Context) error {
	// Verify the certificate signature
	if len(c.Signature) == 0 {
		return ErrNotSigned
	}

	// Create a verifier wallet
	verifier, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{Type: wallet.ProtoWalletArgsTypeAnyone})
	if err != nil {
		return fmt.Errorf("failed to create verifier wallet: %w", err)
	}

	// Get the binary representation without the signature
	data, err := c.ToBinary(false)
	if err != nil {
		return fmt.Errorf("failed to serialize certificate: %w", err)
	}

	// Parse the signature
	signature, err := ec.ParseSignature(c.Signature)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %w", err)
	}

	// Verify the signature using the certifier's public key
	verifyArgs := wallet.VerifySignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
				Protocol:      "certificate signature",
			},
			KeyID: fmt.Sprintf("%s %s", c.Type, c.SerialNumber),
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: &c.Certifier,
			},
		},
		Data:      data,
		Signature: signature,
	}

	verifyResult, err := verifier.VerifySignature(ctx, verifyArgs, "")
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
func (c *Certificate) Sign(ctx context.Context, certifierWallet CertifierWallet) error {
	if c.Signature != nil {
		return ErrAlreadySigned
	}

	// Get the wallet's identity public key and update the certificate's certifier field
	pubKeyResult, err := certifierWallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, "")
	if err != nil {
		return fmt.Errorf("failed to get wallet identity key: %w", err)
	}
	c.Certifier = *pubKeyResult.PublicKey

	// Prepare for signing - exclude the signature when signing
	dataToSign, err := c.ToBinary(false)
	if err != nil {
		return fmt.Errorf("failed to serialize certificate: %w", err)
	}

	// Create signature with the certifier's wallet
	signArgs := wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
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
	signResult, err := certifierWallet.CreateSignature(ctx, signArgs, "go-sdk")
	if err != nil {
		return fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Store the signature
	c.Signature = signResult.Signature.Serialize()

	return nil
}

func (c *Certificate) ToWalletCertificate() (*wallet.Certificate, error) {
	// Convert StringBase64 type to CertificateType [32]byte
	certType, err := c.Type.ToArray()
	if err != nil {
		return nil, fmt.Errorf("invalid certificate type: %w", err)
	}

	// Convert StringBase64 serial number to SerialNumber [32]byte
	serialNumber, err := c.SerialNumber.ToArray()
	if err != nil {
		return nil, fmt.Errorf("invalid serial number: %w", err)
	}

	// Convert Fields map from map[CertificateFieldNameUnder50Bytes]StringBase64 to map[string]string
	fields := make(map[string]string)
	for fieldName, fieldValue := range c.Fields {
		fields[string(fieldName)] = string(fieldValue)
	}

	// Convert []byte signature to *ec.Signature
	var signature *ec.Signature
	if len(c.Signature) > 0 {
		if sig, err := ec.ParseSignature(c.Signature); err == nil {
			signature = sig
		}
	}

	return &wallet.Certificate{
		Type:               certType,
		SerialNumber:       serialNumber,
		Subject:            &c.Subject,   // Convert value type to pointer
		Certifier:          &c.Certifier, // Convert value type to pointer
		RevocationOutpoint: c.RevocationOutpoint,
		Fields:             fields,
		Signature:          signature,
	}, nil
}

func FromWalletCertificate(walletCert *wallet.Certificate) (*Certificate, error) {
	if walletCert == nil {
		return nil, fmt.Errorf("wallet certificate cannot be nil")
	}

	// Convert CertificateType [32]byte to StringBase64
	certType := wallet.StringBase64FromArray(walletCert.Type)

	// Convert SerialNumber [32]byte to StringBase64
	serialNumber := wallet.StringBase64FromArray(walletCert.SerialNumber)

	// Convert ec.PublicKey to ec.PublicKey
	var subject, certifier ec.PublicKey
	if walletCert.Subject != nil {
		subject = *walletCert.Subject
	}
	if walletCert.Certifier != nil {
		certifier = *walletCert.Certifier
	}

	// Convert fields map from map[string]string to map[CertificateFieldNameUnder50Bytes]StringBase64
	fields := make(map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64)
	for fieldName, fieldValue := range walletCert.Fields {
		fields[wallet.CertificateFieldNameUnder50Bytes(fieldName)] = wallet.StringBase64(fieldValue)
	}

	var signature []byte
	if walletCert.Signature != nil {
		signature = walletCert.Signature.Serialize()
	}

	return &Certificate{
		Type:               certType,
		SerialNumber:       serialNumber,
		Subject:            subject,
		Certifier:          certifier,
		RevocationOutpoint: walletCert.RevocationOutpoint,
		Fields:             fields,
		Signature:          signature,
	}, nil
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
