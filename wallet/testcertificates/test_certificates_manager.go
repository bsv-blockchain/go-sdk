package testcertificates

import (
	"context"
	"encoding/base64"
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

const DefaultCertifierPrivKeyHex = "a4ba93def94ee38d2fae8c5948e2daab5c490225ef5be35eb64ce314e0985c28"

var defaultCertifier *ec.PrivateKey

// DefaultCertifier returns a private key of Certifier used by default in test certificates.
func DefaultCertifier() *ec.PrivateKey {
	if defaultCertifier == nil {
		var err error
		defaultCertifier, err = ec.PrivateKeyFromHex(DefaultCertifierPrivKeyHex)
		if err != nil {
			panic(fmt.Errorf("invalid test setup: failed to create default certifier: %w", err))
		}
	}
	return defaultCertifier
}

type ManagerOptions struct {
	doNotAssignToSubjectWallet bool
}

// WithSkipAssignToSubjectWallet by default on creation Manager will assign itself as a certificates manager in wallet.TestWallet.
// Use this option to skip assignment to wallet.TestWallet as a certificate manager.
// This is useful if you just want to create some certificates without changing subject wallet.TestWallet behavior.
func WithSkipAssignToSubjectWallet() func(*ManagerOptions) {
	return func(opts *ManagerOptions) {
		opts.doNotAssignToSubjectWallet = true
	}
}

// ensure manager is implementing wallet.CertificatesManagement interface
var _ wallet.CertificatesManagement = (*Manager)(nil)

type Manager struct {
	t             testing.TB
	subjectWallet *wallet.TestWallet
	certs         []managedCertificate
}

type managedCertificate struct {
	*wallet.Certificate
	master *certificates.MasterCertificate
}

func NewManager(t testing.TB, subjectWallet *wallet.TestWallet, opts ...func(*ManagerOptions)) *Manager {
	options := ManagerOptions{}

	for _, opt := range opts {
		opt(&options)
	}

	m := &Manager{
		t:             t,
		subjectWallet: subjectWallet,
		certs:         make([]managedCertificate, 0),
	}

	if !options.doNotAssignToSubjectWallet {
		subjectWallet.UseCertificatesManager(m)
	}

	return m
}

func (m *Manager) AcquireCertificate(_ context.Context, _ wallet.AcquireCertificateArgs, _ string) (*wallet.Certificate, error) {
	panic("acquiring certificates in test certificates manager not implemented yet, use CertificateForTest() instead")
}

func (m *Manager) ListCertificates(_ context.Context, args wallet.ListCertificatesArgs, _ string) (*wallet.ListCertificatesResult, error) {
	result := &wallet.ListCertificatesResult{
		TotalCertificates: uint32(len(m.certs)),
		Certificates:      make([]wallet.CertificateResult, 0, len(m.certs)),
	}

	for _, cert := range m.certs {
		if slices.Contains(args.Types, cert.Type) && slices.ContainsFunc(args.Certifiers, func(c *ec.PublicKey) bool {
			return c.IsEqual(cert.Certifier)
		}) {
			result.Certificates = append(result.Certificates, wallet.CertificateResult{Certificate: *cert.Certificate})
		}
	}

	return result, nil
}

func (m *Manager) ProveCertificate(ctx context.Context, args wallet.ProveCertificateArgs, _ string) (*wallet.ProveCertificateResult, error) {
	masterCert, err := m.findMasterCertificate(args)
	if err != nil {
		return nil, err
	}

	keyringForVerifier, err := m.keyring(ctx, masterCert, args.FieldsToReveal, args.Verifier)
	if err != nil {
		return nil, err
	}

	keyring := make(map[string]string, 0)
	for field, key := range keyringForVerifier {
		keyring[string(field)] = string(key)
	}

	return &wallet.ProveCertificateResult{
		KeyringForVerifier: keyring,
	}, nil
}

func (m *Manager) findMasterCertificate(args wallet.ProveCertificateArgs) (*certificates.MasterCertificate, error) {
	var masterCert *certificates.MasterCertificate

	for _, cert := range m.certs {
		if args.Certificate.Type == cert.Type && args.Certificate.Certifier.IsEqual(cert.Certifier) && args.Certificate.SerialNumber == cert.SerialNumber {
			masterCert = cert.master
			break
		}
	}

	if masterCert == nil {
		return nil, fmt.Errorf("certificate not found")
	}
	return masterCert, nil
}

func (m *Manager) keyring(ctx context.Context, masterCert *certificates.MasterCertificate, fieldsToReveal []string, verifier *ec.PublicKey) (map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64, error) {
	fieldsName := make([]wallet.CertificateFieldNameUnder50Bytes, len(fieldsToReveal))

	for i, name := range fieldsToReveal {
		fieldsName[i] = wallet.CertificateFieldNameUnder50Bytes(name)
	}

	keyringForVerifier, err := certificates.CreateKeyringForVerifier(
		ctx,
		m.subjectWallet,
		wallet.Counterparty{
			Counterparty: &masterCert.Certifier,
			Type:         wallet.CounterpartyTypeOther,
		},
		wallet.Counterparty{
			Counterparty: verifier,
			Type:         wallet.CounterpartyTypeOther,
		},
		masterCert.Fields,
		fieldsName,
		masterCert.MasterKeyring,
		masterCert.SerialNumber,
		false,
		"",
	)
	if err != nil {
		return nil, err
	}
	return keyringForVerifier, nil
}

func (m *Manager) RelinquishCertificate(_ context.Context, args wallet.RelinquishCertificateArgs, _ string) (*wallet.RelinquishCertificateResult, error) {
	for i, cert := range m.certs {
		if args.Type == cert.Type && args.Certifier.IsEqual(cert.Certifier) && args.SerialNumber == cert.SerialNumber {
			m.certs = append(m.certs[:i], m.certs[i+1:]...)
		}
	}

	return &wallet.RelinquishCertificateResult{Relinquished: true}, nil
}

// CertificateForTest allows you to issue and store valid certificate for this wallet owner for testing.
func (m *Manager) CertificateForTest() TestCertificateOperations {
	return &testCertificateOperations{
		t:       m.t,
		wallet:  m.subjectWallet,
		manager: m,
		fields:  make(map[string]string),
	}
}

// Clear Removes all previously issued certificates from this test wallet
func (m *Manager) Clear() {
	m.certs = make([]managedCertificate, 0)
}

type TestCertificateOperations interface {
	// Clear Removes all previously issued certificates from this test wallet
	Clear()

	// WithType chooses the type of certificate and returns builder for further configuration.
	WithType(string) TestCertificateBuilder
}

type TestCertificateBuilder interface {
	// WithFieldValue sets a single field value in the certificate.
	WithFieldValue(fieldName string, fieldValue string) TestCertificateIssuableFieldBuilder

	// WithFieldValues adds provided fields values map to the certificate.
	WithFieldValues(fields map[string]string) TestCertificateIssuableFieldBuilder
}

type TestCertificateIssuableFieldBuilder interface {
	TestCertificateBuilder

	// Issue will issue the master certificate using DefaultCertifier and store as like it would be in wallet storage.
	Issue() IssuedCertificate

	// IssueWithCertifier will issue the master certificate using provided certifier and store as like it would be in wallet storage.
	IssueWithCertifier(certifier *ec.PrivateKey) IssuedCertificate
}

type testCertificateOperations struct {
	t        testing.TB
	wallet   *wallet.TestWallet
	manager  *Manager
	certType wallet.CertificateType
	fields   map[string]string
}

func (o *testCertificateOperations) Clear() {
	o.manager.Clear()
}

func (o *testCertificateOperations) WithType(typeName string) TestCertificateBuilder {
	var err error
	o.certType, err = wallet.CertificateTypeFromString(typeName)
	require.NoError(o.t, err, "invalid certificate type")
	return o
}

func (o *testCertificateOperations) WithFieldValue(fieldName string, fieldValue string) TestCertificateIssuableFieldBuilder {
	o.fields[fieldName] = fieldValue
	return o
}

func (o *testCertificateOperations) WithFieldValues(fields map[string]string) TestCertificateIssuableFieldBuilder {
	for k, v := range fields {
		o.fields[k] = v
	}
	return o
}

func (o *testCertificateOperations) Issue() IssuedCertificate {
	return o.IssueWithCertifier(DefaultCertifier())
}

func (o *testCertificateOperations) IssueWithCertifier(certifier *ec.PrivateKey) IssuedCertificate {
	ctx := o.t.Context()

	certifierWallet, err := wallet.NewCompletedProtoWallet(certifier)
	require.NoError(o.t, err, "failed to create wallet from certifier")

	certTypeBase64 := base64.StdEncoding.EncodeToString(o.certType.Bytes())
	subjectIdentityKey, err := o.wallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{IdentityKey: true}, "")
	require.NoError(o.t, err, "failed to get subject identity key")

	masterCert, err := certificates.IssueCertificateForSubject(
		ctx,
		certifierWallet,
		wallet.Counterparty{
			Counterparty: subjectIdentityKey.PublicKey,
			Type:         wallet.CounterpartyTypeOther,
		},
		o.fields,
		certTypeBase64,
		func(serial string) (*transaction.Outpoint, error) {
			return &transaction.Outpoint{
				Txid:  chainhash.Hash{},
				Index: 0,
			}, nil
		},
		"", // Auto-generate serial number
	)
	require.NoError(o.t, err, "failed to create master certificate: invalid test setup")
	require.NotNil(o.t, masterCert, "failed to create master certificate")

	walletCert, err := masterCert.ToWalletCertificate()
	require.NoError(o.t, err, "failed to convert master certificate to wallet certificate")

	o.manager.certs = append(o.manager.certs, managedCertificate{
		Certificate: walletCert,
		master:      masterCert,
	})

	return IssuedCertificate{
		manager:    o.manager,
		WalletCert: walletCert,
		MasterCert: masterCert,
	}
}

// IssuedCertificate represents a certificate that has been issued and stored, including its wallet and master certificates.
type IssuedCertificate struct {
	WalletCert *wallet.Certificate
	MasterCert *certificates.MasterCertificate
	manager    *Manager
}

// ToVerifiableCertificate converts an IssuedCertificate into a VerifiableCertificate for a specified verifier.
// It generates a keyring to enable selective field decryption for authorized verifiers.
// Panics if there's an error during keyring creation.
func (c IssuedCertificate) ToVerifiableCertificate(verifier *ec.PublicKey) *certificates.VerifiableCertificate {
	fieldsToReveal := slices.Collect(maps.Keys(c.WalletCert.Fields))

	keyring, err := c.manager.keyring(context.Background(), c.MasterCert, fieldsToReveal, verifier)
	if err != nil {
		panic(err)
	}

	return &certificates.VerifiableCertificate{
		Certificate: c.MasterCert.Certificate,
		Keyring:     keyring,
	}
}
