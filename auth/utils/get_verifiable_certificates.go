package utils

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
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
	var certificateTypes []wallet.CertificateType
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
		// The certificate type should match exactly with the requested types
		requestedFields, ok := options.RequestedCertificates.CertificateTypes[certResult.Type]
		if !ok || len(requestedFields) == 0 {
			continue // Skip if no fields requested for this type
		}

		proveResult, err := options.Wallet.ProveCertificate(ctx, wallet.ProveCertificateArgs{
			Certificate:      certResult.Certificate,
			FieldsToReveal:   requestedFields,
			Verifier:         options.VerifierIdentityKey,
			Privileged:       &options.Privileged,
			PrivilegedReason: options.PrivilegedReason,
		}, "")
		if err != nil {
			return nil, err
		}
		if proveResult == nil {
			return nil, fmt.Errorf("nil result from ProveCertificate for certificate type: %s", certResult.Type)
		}

		baseCert, err := certificates.FromWalletCertificate(&certResult.Certificate)
		if err != nil {
			return nil, fmt.Errorf("failed to convert wallet certificate to base certificate: %w", err)
		}

		// Create keyring - these should also be base64-encoded
		keyring := make(map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64)
		// Only add keyring entries if KeyringForVerifier is not nil
		if proveResult.KeyringForVerifier != nil {
			for fieldName, value := range proveResult.KeyringForVerifier {
				// Validate that keyring value is base64-encoded
				if _, err := base64.StdEncoding.DecodeString(value); err != nil {
					return nil, fmt.Errorf("keyring field '%s' value '%s' is not valid base64: %w", fieldName, value, err)
				}
				keyring[wallet.CertificateFieldNameUnder50Bytes(fieldName)] = wallet.StringBase64(value)
			}
		}

		// Create verifiable certificate
		verifiableCert := certificates.NewVerifiableCertificate(baseCert, keyring)
		result = append(result, verifiableCert)
	}

	return result, nil
}
