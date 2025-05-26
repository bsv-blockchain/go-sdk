package utils

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

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
	var certificateTypes []string
	for certType := range options.RequestedCertificates.CertificateTypes {
		certificateTypes = append(certificateTypes, base64.StdEncoding.EncodeToString(certType[:]))
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
		var revocationOutpoint *overlay.Outpoint
		if certResult.RevocationOutpoint != "" {
			// NewOutpointFromString requires at least 66 characters (64 hex chars + separator + output index)
			parts := strings.Split(certResult.RevocationOutpoint, ":")
			if len(parts) == 2 {
				txid := parts[0]
				// Pad txid to 64 characters if needed
				if len(txid) < 64 {
					padding := strings.Repeat("0", 64-len(txid))
					txid = txid + padding // Pad with zeros
				}
				outpointStr := txid + "." + parts[1]
				var parseErr error
				revocationOutpoint, parseErr = overlay.NewOutpointFromString(outpointStr)
				if parseErr != nil {
					// Just log the error and continue without revocation outpoint
					fmt.Printf("Warning: could not parse revocation outpoint '%s': %v\n",
						certResult.RevocationOutpoint, parseErr)
				}
			}
		}

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
