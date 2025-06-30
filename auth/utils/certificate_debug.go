package utils

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
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
	if cert.SerialNumber == [32]byte{} {
		errors = append(errors, fmt.Sprintf("SerialNumber (%s) is empty", cert.SerialNumber))
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

// SignCertificateForTest properly signs a certificate for test purposes
// It creates a real signature that will pass verification
func SignCertificateForTest(ctx context.Context, cert wallet.Certificate, signerPrivateKey *ec.PrivateKey) (wallet.Certificate, error) {
	signerWallet, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{Type: wallet.ProtoWalletArgsTypePrivateKey, PrivateKey: signerPrivateKey})
	if err != nil {
		return cert, fmt.Errorf("failed to create wallet from private key: %w", err)
	}

	return SignCertificateWithWalletForTest(ctx, cert, signerWallet)

}

// SignCertificateWithWalletForTest properly signs a certificate for test purposes
// It creates a real signature that will pass verification
func SignCertificateWithWalletForTest(ctx context.Context, cert wallet.Certificate, signerWallet wallet.KeyOperations) (wallet.Certificate, error) {
	// Create a copy of the certificate with encoded fields
	encodedCert := GetEncodedCertificateForDebug(cert)

	// Make sure the certifier is set to the signer's public key
	publicKeyResult, err := signerWallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{IdentityKey: true}, "")
	if err != nil {
		return encodedCert, fmt.Errorf("failed to get identity key of signer: %w", err)
	}

	cert.Certifier = publicKeyResult.PublicKey

	certObj, err := certificates.FromWalletCertificate(&encodedCert)
	if err != nil {
		return encodedCert, fmt.Errorf("failed to convert wallet certificate to base certificate: %w", err)
	}

	// Get binary representation without signature
	dataToSign, err := certObj.ToBinary(false)
	if err != nil {
		return encodedCert, fmt.Errorf("failed to serialize certificate: %w", err)
	}

	certType := base64.StdEncoding.EncodeToString(cert.Type[:])
	certSerial := base64.StdEncoding.EncodeToString(cert.SerialNumber[:])

	args := wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
				Protocol:      "certificate signature",
			},
			KeyID: fmt.Sprintf("%s %s", certType, certSerial),
			Counterparty: wallet.Counterparty{
				Type: wallet.CounterpartyTypeAnyone,
			},
		},
		Data: dataToSign,
	}

	signatureResult, err := signerWallet.CreateSignature(ctx, args, "")
	if err != nil {
		return encodedCert, fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Convert back to wallet.Certificate format
	finalCert := wallet.Certificate{
		Type:               encodedCert.Type,
		SerialNumber:       encodedCert.SerialNumber,
		Subject:            &certObj.Subject,
		Certifier:          &certObj.Certifier,
		RevocationOutpoint: encodedCert.RevocationOutpoint,
		Fields:             encodedCert.Fields,
		Signature:          signatureResult.Signature,
	}

	return finalCert, nil
}
