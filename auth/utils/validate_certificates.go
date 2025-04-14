package utils

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

var (
	ErrEmptyCertificates     = errors.New("empty certificates")
	ErrInvalidCertificate    = errors.New("invalid certificate format")
	ErrCertificateValidation = errors.New("certificate validation failed")
)

// RequestedCertificateTypeIDAndFieldList maps certificate type IDs to required fields
type RequestedCertificateTypeIDAndFieldList map[string][]string

// RequestedCertificateSet represents a set of requested certificates
type RequestedCertificateSet struct {
	// Array of public keys that must have signed the certificates
	Certifiers []string

	// Map of certificate type IDs to field names that must be included
	CertificateTypes RequestedCertificateTypeIDAndFieldList
}

// AuthMessage contains the essential fields needed for certificate validation
type AuthMessage struct {
	// The identity key of the sender
	IdentityKey ec.PublicKey

	// The certificates included in the message
	Certificates []*certificates.VerifiableCertificate
}

// ValidateCertificates validates and processes the certificates received from a peer.
// The certificatesRequested parameter can be nil or a RequestedCertificateSet
func ValidateCertificates(
	verifierWallet wallet.Interface,
	message *AuthMessage,
	certificatesRequested *RequestedCertificateSet,
) error {
	// Check if certificates are provided
	if message.Certificates == nil {
		return fmt.Errorf("no certificates were provided in the AuthMessage")
	}

	// Use a wait group to wait for all certificate validations to complete
	var wg sync.WaitGroup
	errCh := make(chan error, len(message.Certificates))

	// Process each certificate concurrently
	for _, incomingCert := range message.Certificates {
		wg.Add(1)
		go func(cert *certificates.VerifiableCertificate) {
			defer wg.Done()

			// Check that the certificate subject matches the message identity key
			subjectKey := cert.Subject.ToDER()
			messageIdentityKey := message.IdentityKey.ToDER()
			if !bytes.Equal(subjectKey, messageIdentityKey) {
				errCh <- fmt.Errorf(
					"the subject of one of your certificates (\"%x\") is not the same as the request sender (\"%x\")",
					subjectKey,
					messageIdentityKey,
				)
				return
			}

			// Verify Certificate structure and signature
			err := cert.Verify()
			if err != nil {
				errCh <- fmt.Errorf("the signature for the certificate with serial number %s is invalid: %v",
					cert.SerialNumber, err)
				return
			}

			// Check if the certificate matches requested certifiers, types, and fields
			if certificatesRequested != nil {
				certifiers := certificatesRequested.Certifiers
				types := certificatesRequested.CertificateTypes

				// Check certifier matches
				certifierKey := cert.Certifier.ToDERHex()
				if !slices.Contains(certifiers, certifierKey) {
					errCh <- fmt.Errorf(
						"certificate with serial number %s has an unrequested certifier: %s",
						cert.SerialNumber,
						certifierKey,
					)
					return
				}

				// Check type match
				_, typeExists := types[string(cert.Type)]
				if !typeExists {
					errCh <- fmt.Errorf("certificate with type %s was not requested", cert.Type)
					return
				}
			}

			_, err = cert.DecryptFields(verifierWallet, false, "")
			if err != nil {
				errCh <- fmt.Errorf("failed to decrypt certificate fields: %v", err)
				return
			}
		}(incomingCert)
	}

	// Wait for all goroutines to finish
	wg.Wait()
	close(errCh)

	// Check if any errors occurred
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}
