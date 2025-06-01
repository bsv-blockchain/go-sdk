package utils

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/overlay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// GetVerifiableCertificatesOptions contains options for retrieving certificates
type GetVerifiableCertificatesOptions struct {
	Wallet                wallet.Interface
	RequestedCertificates *RequestedCertificateSet
	VerifierIdentityKey   *ec.PublicKey
	Privileged            bool
	PrivilegedReason      string
}

// GetVerifiableCertificates retrieves and prepares verifiable certificates based on the provided options.
// It queries the wallet for certificates matching the requested types and certifiers,
// then creates verifiable certificates with the appropriate fields revealed for the specified verifier.
func GetVerifiableCertificates(ctx context.Context, options *GetVerifiableCertificatesOptions) ([]*certificates.VerifiableCertificate, error) {
	if options == nil {
		return nil, fmt.Errorf("GetVerifiableCertificatesOptions cannot be nil")
	}

	if options.Wallet == nil {
		return nil, fmt.Errorf("options.Wallet cannot be nil")
	}

	if options.RequestedCertificates == nil {
		return []*certificates.VerifiableCertificate{}, nil
	}

	var result []*certificates.VerifiableCertificate

	// Get all certificate types
	var certificateTypes []wallet.Base64Bytes32
	for certType := range options.RequestedCertificates.CertificateTypes {
		certificateTypes = append(certificateTypes, certType)
	}

	// Single query for all certificates
	listResult, err := options.Wallet.ListCertificates(ctx, wallet.ListCertificatesArgs{
		Types:      certificateTypes,
		Certifiers: options.RequestedCertificates.Certifiers,
	}, "")
	if err != nil {
		return nil, err
	}

	if listResult == nil {
		return nil, fmt.Errorf("nil result from ListCertificates")
	}

	// Process each certificate
	for _, certResult := range listResult.Certificates {
		// Skip if certificate is nil or has empty type
		if certResult.Type == [32]byte{} {
			continue
		}

		// Get requested fields for this certificate type
		requestedFields, ok := options.RequestedCertificates.CertificateTypes[certResult.Type]
		if !ok || len(requestedFields) == 0 {
			continue // Skip if no fields requested for this type
		}

		// Prepare verifier hex (empty if no key)
		var verifierHex [33]byte
		if options.VerifierIdentityKey != nil {
			copy(verifierHex[:], options.VerifierIdentityKey.ToDER())
		}

		proveResult, err := options.Wallet.ProveCertificate(ctx, wallet.ProveCertificateArgs{
			Certificate:      certResult.Certificate,
			FieldsToReveal:   requestedFields,
			Verifier:         verifierHex,
			Privileged:       &options.Privileged,
			PrivilegedReason: options.PrivilegedReason,
		}, "")
		if err != nil {
			return nil, err
		}
		if proveResult == nil {
			return nil, fmt.Errorf("nil result from ProveCertificate for certificate type: %s", certResult.Type)
		}

		// Handle short txids in revocation outpoints by padding them
		revocationOutpoint := overlay.NewOutpoint(certResult.RevocationOutpoint.Txid, certResult.RevocationOutpoint.Index)

		// Ensure Type and SerialNumber are properly formatted as base64 strings
		// If not, continue with next certificate but don't fail
		certType := certResult.Type
		certSerialNum := certResult.SerialNumber

		// Create the base certificate
		baseCert := &certificates.Certificate{
			Type:               wallet.Base64String(base64.StdEncoding.EncodeToString(certType[:])),
			SerialNumber:       wallet.Base64String(base64.StdEncoding.EncodeToString(certSerialNum[:])),
			RevocationOutpoint: revocationOutpoint,
			Fields:             make(map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String),
		}

		// Handle Signature
		if len(certResult.Signature) > 0 {
			baseCert.Signature = certResult.Signature
		}

		// Handle nil Subject and Certifier safely
		if certResult.Subject != nil {
			baseCert.Subject = *certResult.Subject
		} else {
			// Initialize with empty public key to avoid nil pointer dereference
			baseCert.Subject = ec.PublicKey{}
		}

		if certResult.Certifier != nil {
			baseCert.Certifier = *certResult.Certifier
		} else {
			// Initialize with empty public key to avoid nil pointer dereference
			baseCert.Certifier = ec.PublicKey{}
		}

		// Add certificate fields
		if certResult.Fields != nil {
			for _, fieldName := range requestedFields {
				if value, ok := certResult.Fields[fieldName]; ok {
					// Check if the field value is valid base64
					if _, err := base64.StdEncoding.DecodeString(value); err != nil {
						// If not, encode it
						value = base64.StdEncoding.EncodeToString([]byte(value))
					}
					baseCert.Fields[wallet.CertificateFieldNameUnder50Bytes(fieldName)] = wallet.Base64String(value)
				}
			}
		}

		// Create keyring
		keyring := make(map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String)
		// Only add keyring entries if KeyringForVerifier is not nil
		if proveResult.KeyringForVerifier != nil {
			for fieldName, value := range proveResult.KeyringForVerifier {
				// Check if the keyring value is valid base64
				if _, err := base64.StdEncoding.DecodeString(value); err != nil {
					// If not, encode it
					value = base64.StdEncoding.EncodeToString([]byte(value))
				}
				keyring[wallet.CertificateFieldNameUnder50Bytes(fieldName)] = wallet.Base64String(value)
			}
		}

		// Create verifiable certificate
		verifiableCert := certificates.NewVerifiableCertificate(baseCert, keyring)
		result = append(result, verifiableCert)
	}

	return result, nil
}
