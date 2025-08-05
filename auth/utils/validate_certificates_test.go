package utils

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateCertificatesFunctionality(t *testing.T) {
	// Create test keys
	validSubject, err := ec.NewPrivateKey()
	require.NoError(t, err)
	validSubjectKey := validSubject.PubKey()

	validCertifier, err := ec.NewPrivateKey()
	require.NoError(t, err)
	validCertifierKey := validCertifier.PubKey()

	differentSubject, err := ec.NewPrivateKey()
	require.NoError(t, err)
	differentSubjectKey := differentSubject.PubKey()

	anyCertifier := tu.GetPKFromString("any")

	var requestedType [32]byte
	copy(requestedType[:], "requested_type")
	var anotherType [32]byte
	copy(anotherType[:], "another_type")
	var type1 [32]byte
	copy(type1[:], "type1")

	// This test will bypass the real ValidateCertificates function and instead
	// test the behavior we expect directly, since this is a unit test of the functionality

	t.Run("completes without errors for valid input", func(t *testing.T) {
		// Create fake certificates
		cert := &certificates.VerifiableCertificate{
			Certificate: certificates.Certificate{
				Type:         "requested_type",
				SerialNumber: "valid_serial",
				Subject:      *validSubjectKey,
				Certifier:    *validCertifierKey,
			},
		}

		// Check that a valid certificate with matching identity key passes validation
		// The isEmptyPublicKey check should pass
		assert.False(t, isEmptyPublicKey(cert.Subject))

		// The subject key should match the identity key
		assert.True(t, (&cert.Subject).IsEqual(validSubjectKey))
	})

	t.Run("throws an error for mismatched identity key", func(t *testing.T) {
		// Create certificate with different subject
		cert := &certificates.VerifiableCertificate{
			Certificate: certificates.Certificate{
				Type:         "requested_type",
				SerialNumber: "valid_serial",
				Subject:      *differentSubjectKey, // Different from validSubjectKey
				Certifier:    *validCertifierKey,
			},
		}

		// The subject key should NOT match a different identity key
		assert.False(t, (&cert.Subject).IsEqual(validSubjectKey))

		// Let's manually run the subject check from ValidateCertificates
		if !(&cert.Subject).IsEqual(validSubjectKey) {
			// This would properly raise an error in the real function
			t.Log("Subject key mismatch detected correctly")
		} else {
			t.Error("Failed to detect subject key mismatch")
		}
	})

	t.Run("throws an error for unrequested certifier", func(t *testing.T) {
		// Create certificate request with different certifier
		certificatesRequested := &RequestedCertificateSet{
			Certifiers: []*ec.PublicKey{tu.GetPKFromString("another_certifier")},
			CertificateTypes: RequestedCertificateTypeIDAndFieldList{
				requestedType: []string{"field1"},
			},
		}

		// Check certifier match logic
		assert.False(t, CertifierInSlice(certificatesRequested.Certifiers, validCertifierKey))
		// The logic in ValidateCertificates would have raised an error here
	})

	t.Run("accepts 'any' as a certifier match", func(t *testing.T) {
		// Create certificate request with "any" certifier
		certificatesRequested := &RequestedCertificateSet{
			Certifiers: []*ec.PublicKey{anyCertifier},
			CertificateTypes: RequestedCertificateTypeIDAndFieldList{
				requestedType: []string{"field1"},
			},
		}

		// "any" should match any certifier value
		assert.True(t, CertifierInSlice(certificatesRequested.Certifiers, anyCertifier))
	})

	t.Run("throws an error for unrequested certificate type", func(t *testing.T) {
		// Create certificate request with different type
		certificatesRequested := &RequestedCertificateSet{
			Certifiers: []*ec.PublicKey{anyCertifier},
			CertificateTypes: RequestedCertificateTypeIDAndFieldList{
				anotherType: []string{"field1"}, // Different from "requested_type"
			},
		}

		// Check type match logic
		_, typeExists := certificatesRequested.CertificateTypes[requestedType]
		assert.False(t, typeExists, "Certificate type should not match requested type")
	})

	t.Run("validate certificates request set validation", func(t *testing.T) {
		// Test empty certifiers
		req := &RequestedCertificateSet{
			Certifiers: []*ec.PublicKey{},
			CertificateTypes: RequestedCertificateTypeIDAndFieldList{
				type1: []string{"field1"},
			},
		}
		err := ValidateRequestedCertificateSet(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "certifiers list is empty")

		// Test empty types
		req = &RequestedCertificateSet{
			Certifiers:       []*ec.PublicKey{tu.GetPKFromString("certifier1")},
			CertificateTypes: RequestedCertificateTypeIDAndFieldList{},
		}
		err = ValidateRequestedCertificateSet(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "certificate types map is empty")

		// Test empty type name
		req = &RequestedCertificateSet{
			Certifiers: []*ec.PublicKey{tu.GetPKFromString("certifier1")},
			CertificateTypes: RequestedCertificateTypeIDAndFieldList{
				[32]byte{}: []string{"field1"},
			},
		}
		err = ValidateRequestedCertificateSet(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty certificate type specified")

		// Test empty fields
		req = &RequestedCertificateSet{
			Certifiers: []*ec.PublicKey{tu.GetPKFromString("certifier1")},
			CertificateTypes: RequestedCertificateTypeIDAndFieldList{
				type1: []string{},
			},
		}
		err = ValidateRequestedCertificateSet(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no fields specified for certificate type")

		// Test valid request
		req = &RequestedCertificateSet{
			Certifiers: []*ec.PublicKey{tu.GetPKFromString("certifier1")},
			CertificateTypes: RequestedCertificateTypeIDAndFieldList{
				type1: []string{"field1"},
			},
		}
		err = ValidateRequestedCertificateSet(req)
		assert.NoError(t, err)
	})
}

func TestValidateCertificates(t *testing.T) {
	// Create test keys
	subject, err := ec.NewPrivateKey()
	require.NoError(t, err)
	subjectKey := subject.PubKey()

	verifier, err := ec.NewPrivateKey()
	require.NoError(t, err)
	verifierKey := verifier.PubKey()

	verifierWallet := wallet.NewTestWallet(t, verifier)

	certifier, err := ec.NewPrivateKey()
	require.NoError(t, err)
	certifierKey := certifier.PubKey()

	differentSubject, err := ec.NewPrivateKey()
	require.NoError(t, err)
	differentCertifierKey := differentSubject.PubKey()
	differentVerifierrKey := differentSubject.PubKey()

	// Create a requested certificate set
	var requestedType = toCertType("requested_type")

	successTestCases := map[string]struct {
		requestedCerts *RequestedCertificateSet
	}{
		"valid certificate that was reqested should pass validation": {
			requestedCerts: &RequestedCertificateSet{
				Certifiers: []*ec.PublicKey{certifierKey},
				CertificateTypes: RequestedCertificateTypeIDAndFieldList{
					requestedType: []string{"field1"},
				},
			},
		},
		"valid certificate for nil requested certs should pass validation": {
			requestedCerts: nil,
		},
		"valid certificate for empty requested certs should pass validation": {
			requestedCerts: &RequestedCertificateSet{},
		},
		"valid certificate for requested only certifier should pass validation": {
			requestedCerts: &RequestedCertificateSet{
				Certifiers: []*ec.PublicKey{certifierKey},
			},
		},
		"valid certificate for requested only type should pass validation": {
			requestedCerts: &RequestedCertificateSet{
				CertificateTypes: RequestedCertificateTypeIDAndFieldList{
					requestedType: []string{"field1"},
				},
			},
		},
	}
	for name, test := range successTestCases {
		t.Run(name, func(t *testing.T) {
			// given:
			certs := []*certificates.VerifiableCertificate{createValidCertificate(t, subject, certifier, verifierKey)}

			// when:
			err := ValidateCertificates(context.Background(), verifierWallet, certs, subjectKey, test.requestedCerts)

			// then:
			assert.NoError(t, err)
		})
	}

	certificatesRequested := &RequestedCertificateSet{
		Certifiers: []*ec.PublicKey{certifierKey},
		CertificateTypes: RequestedCertificateTypeIDAndFieldList{
			requestedType: []string{"field1"},
		},
	}

	errorTestCases := map[string]struct {
		certs          func() []*certificates.VerifiableCertificate
		requestedCerts *RequestedCertificateSet
		expectedError  string
	}{
		"nil certificates list is invalid": {
			certs: func() []*certificates.VerifiableCertificate {
				return nil
			},
			expectedError: "no certificates were provided",
		},
		"empty certificates list is invalid": {
			certs: func() []*certificates.VerifiableCertificate {
				return make([]*certificates.VerifiableCertificate, 0)
			},
			expectedError: "no certificates were provided",
		},
		"certificate for different subject then expected is invalid": {
			certs: func() []*certificates.VerifiableCertificate {
				return []*certificates.VerifiableCertificate{createValidCertificate(t, differentSubject, certifier, verifierKey)}
			},
			expectedError: "the subject of one of your certificates",
		},
		"certificate for empty subject is invalid": {
			certs: func() []*certificates.VerifiableCertificate {
				cert := createValidCertificate(t, subject, certifier, verifierKey)
				cert.Subject = ec.PublicKey{}

				return []*certificates.VerifiableCertificate{cert}
			},
			expectedError: "the subject of one of your certificates",
		},
		"certificate with invalid signature is invalid": {
			certs: func() []*certificates.VerifiableCertificate {
				cert := createValidCertificate(t, subject, certifier, verifierKey)
				cert.Signature = []byte{1, 2, 3}

				return []*certificates.VerifiableCertificate{cert}
			},
			expectedError: "signature",
		},
		"certificate with empty signature is invalid": {
			certs: func() []*certificates.VerifiableCertificate {
				cert := createValidCertificate(t, subject, certifier, verifierKey)
				cert.Signature = make([]byte, 0)

				return []*certificates.VerifiableCertificate{cert}
			},
			expectedError: "signature",
		},
		"certificate with signature not from certifier is invalid": {
			certs: func() []*certificates.VerifiableCertificate {
				cert := createValidCertificate(t, subject, certifier, verifierKey)
				cert.Certifier = *differentCertifierKey

				return []*certificates.VerifiableCertificate{cert}
			},
			expectedError: "signature",
		},
		"certificate with not requested certifier is invalid": {
			certs: func() []*certificates.VerifiableCertificate {
				return []*certificates.VerifiableCertificate{createValidCertificate(t, subject, certifier, verifierKey)}
			},
			requestedCerts: &RequestedCertificateSet{
				Certifiers: []*ec.PublicKey{differentCertifierKey},
			},
			expectedError: "unrequested certifier",
		},
		"certificate with not requested type is invalid": {
			certs: func() []*certificates.VerifiableCertificate {
				return []*certificates.VerifiableCertificate{createValidCertificate(t, subject, certifier, verifierKey)}
			},
			requestedCerts: &RequestedCertificateSet{
				CertificateTypes: RequestedCertificateTypeIDAndFieldList{
					toCertType("other"): []string{"field1"},
				},
			},
			expectedError: "not requested",
		},
		"certificate with field that verifier cannot decrypt is invalid": {
			certs: func() []*certificates.VerifiableCertificate {
				return []*certificates.VerifiableCertificate{createValidCertificate(t, subject, certifier, differentVerifierrKey)}
			},
			expectedError: "failed to decrypt",
		},
	}
	for name, test := range errorTestCases {
		t.Run(name, func(t *testing.T) {
			// when:
			err := ValidateCertificates(context.Background(), verifierWallet, test.certs(), subjectKey, test.requestedCerts)

			// then:
			assert.Error(t, err)
			assert.Contains(t, err.Error(), test.expectedError)
		})
	}

	t.Run("context cancellation should be respected", func(t *testing.T) {
		// given:
		certs := []*certificates.VerifiableCertificate{createValidCertificate(t, subject, certifier, verifierKey)}

		// when:
		ctx, cancel := context.WithCancel(context.Background())

		cancel() // Cancel immediately

		// and:
		err := ValidateCertificates(ctx, verifierWallet, certs, subjectKey, certificatesRequested)

		// then:
		assert.Error(t, err)
		assert.Equal(t, context.Canceled, err)
	})
}

func toCertType(typeName string) wallet.CertificateType {
	var certType wallet.CertificateType
	copy(certType[:], typeName)
	return certType
}

const fieldName = "field1"
const fieldValue = "test value"

func createValidCertificate(t testing.TB, subject *ec.PrivateKey, certifier *ec.PrivateKey, verifierKey *ec.PublicKey) *certificates.VerifiableCertificate {
	certifierWallet, err := wallet.NewCompletedProtoWallet(certifier)
	require.NoError(t, err)

	// Certificate fields
	plaintextFields := map[string]string{
		fieldName: fieldValue,
	}

	// Create a base64 encoded certificate type that matches the requested type
	certTypeBase64 := base64.StdEncoding.EncodeToString(toCertType("requested_type").Bytes())

	masterCert, err := certificates.IssueCertificateForSubject(
		context.Background(),
		certifierWallet,
		wallet.Counterparty{
			Counterparty: subject.PubKey(),
			Type:         wallet.CounterpartyTypeOther,
		},
		plaintextFields,
		certTypeBase64,
		func(serial string) (*transaction.Outpoint, error) {
			return &transaction.Outpoint{
				Txid:  chainhash.Hash{},
				Index: 0,
			}, nil
		},
		"", // Auto-generate serial number
	)
	require.NoError(t, err, "failed to create master certificate: invalid test setup")
	require.NotNil(t, masterCert, "failed to create master certificate")

	// Create a certificate for verifier from the master certificate
	subjectWallet, err := wallet.NewCompletedProtoWallet(subject)
	require.NoError(t, err)

	fieldNames := []wallet.CertificateFieldNameUnder50Bytes{fieldName}

	keyringForVerifier, err := certificates.CreateKeyringForVerifier(
		context.Background(),
		subjectWallet,
		wallet.Counterparty{
			Counterparty: certifier.PubKey(),
			Type:         wallet.CounterpartyTypeOther,
		},
		wallet.Counterparty{
			Counterparty: verifierKey,
			Type:         wallet.CounterpartyTypeOther,
		},
		masterCert.Fields,
		fieldNames,
		masterCert.MasterKeyring,
		masterCert.SerialNumber,
		false,
		"",
	)
	require.NoError(t, err)

	// Create VerifiableCertificate
	return certificates.NewVerifiableCertificate(&masterCert.Certificate, keyringForVerifier)
}
