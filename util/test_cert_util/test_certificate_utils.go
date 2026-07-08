package tcu

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/testcertificates"
)

const (
	CertificateFieldName                          = "field1"
	CertificateFieldValue                         = "test value"
	CertificateTypeName   testCertificateTypeName = "requested_type"
)

type testCertificateTypeName string

func (ct testCertificateTypeName) String() string {
	return string(ct)
}

func (ct testCertificateTypeName) ToType(t testing.TB) wallet.CertificateType {
	certType, err := wallet.CertificateTypeFromString(ct.String())
	require.NoError(t, err, "invalid test setup: invalid certificate type")
	return certType
}

func CreateValidCertificate(t testing.TB, subject, certifier *ec.PrivateKey, verifierKey *ec.PublicKey) *certificates.VerifiableCertificate {
	subjectWallet := wallet.NewTestWallet(t, subject)

	certManager := testcertificates.NewManager(t, subjectWallet)

	verifiableCert := certManager.CertificateForTest().WithType(CertificateTypeName.String()).
		WithFieldValue(CertificateFieldName, CertificateFieldValue).
		IssueWithCertifier(certifier).
		ToVerifiableCertificate(verifierKey)

	return verifiableCert
}
