package tcu

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/testcertificates"
	"github.com/stretchr/testify/require"
)

const CertificateFieldName = "field1"
const CertificateFieldValue = "test value"
const CertificateTypeName testCertificateTypeName = "requested_type"

type testCertificateTypeName string

func (ct testCertificateTypeName) String() string {
	return string(ct)
}

func (ct testCertificateTypeName) ToType(t testing.TB) wallet.CertificateType {
	certType, err := wallet.CertificateTypeFromString(ct.String())
	require.NoError(t, err, "invalid test setup: invalid certificate type")
	return certType
}

func CreateValidCertificate(t testing.TB, subject *ec.PrivateKey, certifier *ec.PrivateKey, verifierKey *ec.PublicKey) *certificates.VerifiableCertificate {
	subjectWallet := wallet.NewTestWallet(t, subject)

	certManager := testcertificates.NewManager(t, subjectWallet)

	verifiableCert := certManager.CertificateForTest().WithType(CertificateTypeName.String()).
		WithFieldValue(CertificateFieldName, CertificateFieldValue).
		IssueWithCertifier(certifier).
		ToVerifiableCertificate(verifierKey)

	return verifiableCert
}
