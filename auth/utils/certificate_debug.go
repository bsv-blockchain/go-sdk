package utils

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// ValidateCertificateEncoding checks if a certificate's fields are properly encoded
// and returns detailed error messages for any issues found.
// This is particularly useful for debugging test failures related to certificate encoding.
func ValidateCertificateEncoding(cert wallet.Certificate) []string {
	var errors []string

	// Validate Type
	if cert.Type == [32]byte{} {
		errors = append(errors, fmt.Sprintf("Type (%s) is empty", cert.Type))
	}

	// Validate SerialNumber
	if _, err := base64.StdEncoding.DecodeString(cert.SerialNumber); err != nil {
		errors = append(errors, fmt.Sprintf("SerialNumber (%s) is not valid base64: %v", cert.SerialNumber, err))
	}

	// Validate Fields
	if cert.Fields != nil {
		for fieldName, fieldValue := range cert.Fields {
			if _, err := base64.StdEncoding.DecodeString(fieldValue); err != nil {
				errors = append(errors, fmt.Sprintf("Field %s value (%s) is not valid base64: %v", fieldName, fieldValue, err))
			}
		}
	}

	return errors
}

// GetEncodedCertificateForDebug ensures all string fields in a certificate are properly base64 encoded
// This is useful for tests where certificates might be created with raw strings
func GetEncodedCertificateForDebug(cert wallet.Certificate) wallet.Certificate {
	result := cert

	// Encode SerialNumber if necessary
	if _, err := base64.StdEncoding.DecodeString(cert.SerialNumber); err != nil {
		result.SerialNumber = base64.StdEncoding.EncodeToString([]byte(cert.SerialNumber))
	}

	// Encode Fields if necessary
	if cert.Fields != nil {
		result.Fields = make(map[string]string)
		for fieldName, fieldValue := range cert.Fields {
			if _, err := base64.StdEncoding.DecodeString(fieldValue); err != nil {
				result.Fields[fieldName] = base64.StdEncoding.EncodeToString([]byte(fieldValue))
			} else {
				result.Fields[fieldName] = fieldValue
			}
		}
	}

	return result
}

// createRevocationOutpoint creates a valid overlay.Outpoint from a string in format "txid:index"
func createRevocationOutpoint(outpointStr string) (*overlay.Outpoint, error) {
	parts := strings.Split(outpointStr, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid outpoint format, expected 'txid:index', got '%s'", outpointStr)
	}

	// Pad the txid to 64 characters if needed
	txidHex := parts[0]
	for len(txidHex) < 64 {
		txidHex = "0" + txidHex
	}

	// Parse the txid
	txidBytes, err := hex.DecodeString(txidHex)
	if err != nil {
		return nil, fmt.Errorf("invalid txid hex: %w", err)
	}

	// Create a chainhash.Hash
	var txid chainhash.Hash
	copy(txid[:], txidBytes)

	// Parse the output index
	var outputIndex uint32
	_, err = fmt.Sscanf(parts[1], "%d", &outputIndex)
	if err != nil {
		return nil, fmt.Errorf("invalid output index: %w", err)
	}

	return &overlay.Outpoint{
		Txid:        txid,
		OutputIndex: outputIndex,
	}, nil
}

// SignCertificateForTest properly signs a certificate for test purposes
// It creates a real signature that will pass verification
func SignCertificateForTest(ctx context.Context, cert wallet.Certificate, signerPrivateKey *ec.PrivateKey) (wallet.Certificate, error) {
	// Create a copy of the certificate with encoded fields
	encodedCert := GetEncodedCertificateForDebug(cert)

	// Make sure the certifier is set to the signer's public key
	encodedCert.Certifier = signerPrivateKey.PubKey()

	// Parse the revocation outpoint
	outpoint, err := createRevocationOutpoint(encodedCert.RevocationOutpoint)
	if err != nil {
		return encodedCert, fmt.Errorf("failed to parse revocation outpoint: %w", err)
	}

	// Convert wallet.Certificate to certificates.Certificate for signing
	certObj := &certificates.Certificate{
		Type:               wallet.Base64StringFromArray(encodedCert.Type),
		SerialNumber:       wallet.Base64String(encodedCert.SerialNumber),
		Fields:             make(map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String),
		RevocationOutpoint: outpoint,
	}

	// Copy subject and certifier
	if encodedCert.Subject != nil {
		subjectCopy := *encodedCert.Subject
		certObj.Subject = subjectCopy
	}

	// Use the signerPrivateKey's public key as certifier
	certifierPubKey := *signerPrivateKey.PubKey()
	certObj.Certifier = certifierPubKey

	// Convert fields
	for name, value := range encodedCert.Fields {
		certObj.Fields[wallet.CertificateFieldNameUnder50Bytes(name)] = wallet.Base64String(value)
	}

	// Get binary representation without signature
	dataToSign, err := certObj.ToBinary(false)
	if err != nil {
		return encodedCert, fmt.Errorf("failed to serialize certificate: %w", err)
	}

	// Create signature
	signature, err := signerPrivateKey.Sign(dataToSign)
	if err != nil {
		return encodedCert, fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Update the certificate object with the new signature
	certObj.Signature = signature.Serialize()

	// Convert back to wallet.Certificate format
	finalCert := wallet.Certificate{
		Type:               encodedCert.Type,
		SerialNumber:       string(certObj.SerialNumber),
		Subject:            &certObj.Subject,
		Certifier:          &certObj.Certifier,
		RevocationOutpoint: encodedCert.RevocationOutpoint,
		Fields:             encodedCert.Fields,
		Signature:          string(certObj.Signature),
	}

	return finalCert, nil
}
