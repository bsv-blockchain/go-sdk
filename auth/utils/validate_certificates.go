package utils

import (
	"errors"
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
// type AuthMessage struct {
// 	// The identity key of the sender
// 	IdentityKey *ec.PublicKey

// 	// The certificates included in the message
// 	Certificates []*certificates.VerifiableCertificate
// }
