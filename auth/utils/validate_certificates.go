package utils

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

var (
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
	var cancel func()
	ctx, cancel = context.WithCancel(ctx)
	defer cancel()

	workerPoolSize := len(certs)
	if workerPoolSize > runtime.NumCPU() {
		workerPoolSize = runtime.NumCPU()
	}

	// Create a worker pool with number of workers
	certChan := make(chan *certificates.VerifiableCertificate, len(certs))
	errCh := make(chan error, 1)

	// Start worker pool
	for i := 0; i < workerPoolSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cert := range certChan {
				err := ValidateCertificate(ctx, verifierWallet, cert, identityKey, certificatesRequested)
				if err != nil {
					// ensure the go routine won't block on sending to channel
					select {
					case <-ctx.Done():
					case errCh <- fmt.Errorf("certificate validation failed: %w", err):
					default:
					}
				}
			}
		}()
	}

	// Send certificates to workers
	for _, cert := range certs {
		certChan <- cert
	}
	close(certChan)

	done := make(chan struct{})
	// Wait for all workers to finish
	go func() {
		wg.Wait()
		done <- struct{}{}
	}()

	// Check for any errors
	select {
	case err := <-errCh:
		return errors.Join(ErrCertificateValidation, err)
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func ValidateCertificate(
	ctx context.Context,
	verifierWallet wallet.Interface,
	cert *certificates.VerifiableCertificate,
	identityKey *ec.PublicKey,
	certificatesRequested *RequestedCertificateSet,
) error {

	// check for the context end
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := verifySubjectIdentityKey(cert, identityKey); err != nil {
		return err
	}

	// check for the context end
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := cert.Verify(ctx); err != nil {
		return fmt.Errorf("the signature for the certificate with serial number %s is invalid: %w",
			cert.SerialNumber, err)
	}
	if err := verifyForRequestCertificates(cert, certificatesRequested); err != nil {
		return err
	}

	// check for the context end
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if _, err := cert.DecryptFields(ctx, verifierWallet, false, ""); err != nil {
		return fmt.Errorf("failed to decrypt certificate fields: %w", err)
	}

	return nil
}

func verifyForRequestCertificates(cert *certificates.VerifiableCertificate, certificatesRequested *RequestedCertificateSet) error {
	if certificatesRequested == nil {
		return nil
	}

	if err := verifyRequestedCertifier(cert, certificatesRequested); err != nil {
		return err
	}

	return verifyForRequestedType(cert, certificatesRequested)
}

func verifyForRequestedType(cert *certificates.VerifiableCertificate, certificatesRequested *RequestedCertificateSet) error {
	if len(certificatesRequested.CertificateTypes) == 0 {
		return nil
	}

	if cert.Type == "" {
		return nil
	}

	certType, err := cert.Type.ToArray()
	if err != nil {
		return fmt.Errorf("failed to convert certificate type to byte array: %w", err)
	}

	requestedFields, typeExists := certificatesRequested.CertificateTypes[certType]
	if !typeExists {
		return fmt.Errorf("certificate with type %s was not requested", cert.Type)
	}

	// Additional field validation could be done here if needed
	_ = requestedFields

	return nil
}

func verifyRequestedCertifier(cert *certificates.VerifiableCertificate, certificatesRequested *RequestedCertificateSet) error {
	if len(certificatesRequested.Certifiers) == 0 {
		return nil
	}

	if !isEmptyPublicKey(cert.Certifier) && !CertifierInSlice(certificatesRequested.Certifiers, &cert.Certifier) {
		return fmt.Errorf("certificate with serial number %s has an unrequested certifier: %s",
			cert.SerialNumber, cert.Certifier.ToDERHex())
	}
	return nil
}

func verifySubjectIdentityKey(cert *certificates.VerifiableCertificate, identityKey *ec.PublicKey) error {
	subjectPubKey := &cert.Subject
	if isEmptyPublicKey(cert.Subject) || identityKey == nil || !subjectPubKey.IsEqual(identityKey) {
		var subjectStr, identityStr string
		if !isEmptyPublicKey(cert.Subject) {
			subjectStr = cert.Subject.ToDERHex()
		}
		if identityKey != nil {
			identityStr = identityKey.ToDERHex()
		}
		return fmt.Errorf("the subject of one of your certificates (%q) is not the same as the request sender (%q)",
			subjectStr,
			identityStr)
	}
	return nil
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
