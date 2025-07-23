package utils

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
type RequestedCertificateTypeIDAndFieldList map[wallet.CertificateType][]string

func (m RequestedCertificateTypeIDAndFieldList) MarshalJSON() ([]byte, error) {
	tmp := make(map[string][]string)
	for k, v := range m {
		tmp[base64.StdEncoding.EncodeToString(k[:])] = v
	}
	return json.Marshal(tmp)
}

func (m *RequestedCertificateTypeIDAndFieldList) UnmarshalJSON(data []byte) error {
	tmp := make(map[string][]string)
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	result := make(RequestedCertificateTypeIDAndFieldList)
	for k, v := range tmp {
		decoded, err := base64.StdEncoding.DecodeString(k)
		if err != nil {
			return fmt.Errorf("invalid base64 key: %w", err)
		}
		if len(decoded) != 32 {
			return fmt.Errorf("expected 32 bytes, got %d", len(decoded))
		}
		var key wallet.CertificateType
		copy(key[:], decoded)
		result[key] = v
	}
	*m = result
	return nil
}

// RequestedCertificateSet represents a set of requested certificates
type RequestedCertificateSet struct {
	// Array of public keys that must have signed the certificates
	Certifiers []*ec.PublicKey

	// Map of certificate type IDs to field names that must be included
	CertificateTypes RequestedCertificateTypeIDAndFieldList
}

func CertifierInSlice(certifiers []*ec.PublicKey, certifier *ec.PublicKey) bool {
	if certifier == nil {
		return false
	}
	for _, c := range certifiers {
		if c.IsEqual(certifier) {
			return true
		}
	}
	return false
}

// isEmptyPublicKey checks if a public key is empty/uninitialized
func isEmptyPublicKey(key ec.PublicKey) bool {
	return key.X == nil || key.Y == nil
}

// ValidateCertificates validates and processes the certificates received from a peer.
// This matches the TypeScript implementation's validateCertificates function.
func ValidateCertificates(
	ctx context.Context,
	verifierWallet wallet.Interface,
	certs []*certificates.VerifiableCertificate,
	identityKey *ec.PublicKey,
	certificatesRequested *RequestedCertificateSet,
) error {
	if len(certs) == 0 {
		return errors.New("no certificates were provided")
	}

	// Use a wait group to wait for all certificate validations to complete
	var wg sync.WaitGroup
	errCh := make(chan error, len(certs))

	var cancel func()
	ctx, cancel = context.WithCancel(ctx)

	// Process each certificate in a goroutine
	for _, incomingCert := range certs {
		wg.Add(1)
		go func(cert *certificates.VerifiableCertificate) {
			defer wg.Done()

			notifyError := func(err error) {
				select {
				case <-ctx.Done():
					return
				default:
					errCh <- err
				}
			}

			// Check that certificate subject matches identity key
			subjectPubKey := &cert.Subject
			if isEmptyPublicKey(cert.Subject) || identityKey == nil || !subjectPubKey.IsEqual(identityKey) {
				var subjectStr, identityStr string
				if !isEmptyPublicKey(cert.Subject) {
					subjectStr = cert.Subject.ToDERHex()
				}
				if identityKey != nil {
					identityStr = identityKey.ToDERHex()
				}
				notifyError(fmt.Errorf("the subject of one of your certificates (%q) is not the same as the request sender (%q)",
					subjectStr, identityStr))
				return
			}

			// Verify certificate structure and signature
			// this could take some time, so check if context isn't already done
			select {
			case <-ctx.Done():
				return
			default:
				err := cert.Verify(ctx)
				if err != nil {
					notifyError(fmt.Errorf("the signature for the certificate with serial number %s is invalid: %v",
						cert.SerialNumber, err))
					return
				}
			}

			// Check if the certificate matches requested certifiers, types, and fields
			if certificatesRequested != nil {
				// Check certifier matches requested certifiers if any
				if !isEmptyPublicKey(cert.Certifier) && len(certificatesRequested.Certifiers) > 0 {
					certifierKey := &cert.Certifier
					if !CertifierInSlice(certificatesRequested.Certifiers, certifierKey) {
						notifyError(fmt.Errorf("certificate with serial number %s has an unrequested certifier: %x",
							cert.SerialNumber, certifierKey))
						return
					}
				}

				// Check type match
				if cert.Type != "" {
					certType, err := cert.Type.ToArray()
					if err != nil {
						notifyError(fmt.Errorf("failed to convert certificate type to byte array: %v", err))
						return
					}
					requestedFields, typeExists := certificatesRequested.CertificateTypes[certType]
					if !typeExists {
						notifyError(fmt.Errorf("certificate with type %s was not requested", cert.Type))
						return
					}

					// Additional field validation could be done here if needed
					_ = requestedFields
				}
			}

			// Attempt to decrypt fields
			// this could take some time, so check if the context isn't already done
			select {
			case <-ctx.Done():
				return
			default:
				_, err := cert.DecryptFields(ctx, verifierWallet, false, "")
				if err != nil {
					notifyError(fmt.Errorf("failed to decrypt certificate fields: %v", err))
					return
				}
			}
			// If we reach here, this certificate is valid
		}(incomingCert)
	}

	done := make(chan struct{})
	// Wait for all goroutines to finish
	go func() {
		wg.Wait()
		done <- struct{}{}
	}()

	// Check for any errors
	select {
	case err := <-errCh:
		cancel()
		return err
	case <-done:
		cancel()
		return nil
	case <-ctx.Done():
		cancel()
		return ctx.Err()
	}
}

// ValidateRequestedCertificateSet validates that a RequestedCertificateSet is properly formatted
func ValidateRequestedCertificateSet(req *RequestedCertificateSet) error {
	if req == nil {
		return errors.New("requested certificate set is nil")
	}

	if len(req.Certifiers) == 0 {
		return errors.New("certifiers list is empty")
	}

	if len(req.CertificateTypes) == 0 {
		return errors.New("certificate types map is empty")
	}

	for certType, fields := range req.CertificateTypes {
		if certType == [32]byte{} {
			return errors.New("empty certificate type specified")
		}

		if len(fields) == 0 {
			return fmt.Errorf("no fields specified for certificate type: %s", certType)
		}
	}

	return nil
}
