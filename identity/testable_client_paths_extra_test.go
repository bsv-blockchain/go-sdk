package identity

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// newTestableClientForPaths builds a TestableIdentityClient backed by a mockable
// wallet and a permissive certificate verifier, plus a minimal certificate.
func newTestableClientForPaths(t *testing.T, keyInt int) (*TestableIdentityClient, *wallet.TestWallet, *wallet.Certificate) {
	t.Helper()
	privKey, pubKey := privateKeyFromInt(keyInt)
	mockWallet := wallet.NewTestWallet(t, privKey)
	client, err := NewTestableIdentityClient(mockWallet, nil, "", &MockCertificateVerifier{})
	require.NoError(t, err)
	cert := &wallet.Certificate{
		Subject: pubKey,
		Fields:  map[string]string{"name": "Alice"},
	}
	return client, mockWallet, cert
}

func TestTestablePubliclyRevealAttributesValidation(t *testing.T) {
	t.Run("no fields on certificate", func(t *testing.T) {
		client, _, _ := newTestableClientForPaths(t, 310)
		cert := &wallet.Certificate{Fields: map[string]string{}}
		_, _, err := client.PubliclyRevealAttributes(context.Background(), cert, []CertificateFieldNameUnder50Bytes{"name"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no fields to reveal")
	})

	t.Run("no fields requested", func(t *testing.T) {
		client, _, cert := newTestableClientForPaths(t, 311)
		_, _, err := client.PubliclyRevealAttributes(context.Background(), cert, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "at least one field")
	})
}

func TestTestablePubliclyRevealAttributesProveCertificateError(t *testing.T) {
	client, mockWallet, cert := newTestableClientForPaths(t, 312)
	mockWallet.OnProveCertificate().ReturnError(fmt.Errorf("prove failed"))

	_, _, err := client.PubliclyRevealAttributes(context.Background(), cert, []CertificateFieldNameUnder50Bytes{"name"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to prove certificate")
}

func TestTestablePubliclyRevealAttributesLockError(t *testing.T) {
	client, mockWallet, cert := newTestableClientForPaths(t, 313)
	mockWallet.OnProveCertificate().ReturnSuccess(&wallet.ProveCertificateResult{
		KeyringForVerifier: map[string]string{"k": "v"},
	})
	mockWallet.OnCreateSignature().ReturnError(fmt.Errorf("cannot sign"))

	_, _, err := client.PubliclyRevealAttributes(context.Background(), cert, []CertificateFieldNameUnder50Bytes{"name"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to create locking script")
}

func TestTestablePubliclyRevealAttributesCreateActionError(t *testing.T) {
	client, mockWallet, cert := newTestableClientForPaths(t, 314)
	mockWallet.OnProveCertificate().ReturnSuccess(&wallet.ProveCertificateResult{
		KeyringForVerifier: map[string]string{"k": "v"},
	})
	mockWallet.OnCreateSignature().ReturnSuccess(&wallet.CreateSignatureResult{
		Signature: &ec.Signature{R: big.NewInt(1), S: big.NewInt(1)},
	})
	mockWallet.OnCreateAction().ReturnError(fmt.Errorf("cannot create action"))

	_, _, err := client.PubliclyRevealAttributes(context.Background(), cert, []CertificateFieldNameUnder50Bytes{"name"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to create action")
}
