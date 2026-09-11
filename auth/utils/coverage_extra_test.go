package utils_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	tcu "github.com/bsv-blockchain/go-sdk/util/test_cert_util"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// TestCreateNonceError covers the CreateHMAC error branch of CreateNonce.
func TestCreateNonceError(t *testing.T) {
	t.Run("returns error when wallet CreateHMAC fails", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t)
		tw.OnCreateHMAC().ReturnError(errors.New("boom"))

		nonce, err := utils.CreateNonce(context.Background(), tw, wallet.Counterparty{
			Type: wallet.CounterpartyTypeSelf,
		})
		require.Error(t, err)
		assert.Empty(t, nonce)
		require.Contains(t, err.Error(), "failed to create HMAC")
	})
}

// TestVerifyNonceError covers the VerifyHMAC error branch of VerifyNonce.
func TestVerifyNonceError(t *testing.T) {
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	counterparty := wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}

	t.Run("returns error when wallet VerifyHMAC fails", func(t *testing.T) {
		// Build a well-formed nonce with a real wallet first.
		realWallet, err := wallet.NewCompletedProtoWallet(privKey)
		require.NoError(t, err)
		nonce, err := utils.CreateNonce(context.Background(), realWallet, counterparty)
		require.NoError(t, err)

		tw := wallet.NewTestWallet(t, privKey)
		tw.OnVerifyHMAC().ReturnError(errors.New("verify boom"))

		valid, err := utils.VerifyNonce(context.Background(), nonce, tw, counterparty)
		require.Error(t, err)
		assert.False(t, valid)
		require.Contains(t, err.Error(), "failed to verify HMAC")
	})
}

// TestCertifierInSliceNil covers the nil-certifier branch of CertifierInSlice.
func TestCertifierInSliceNil(t *testing.T) {
	t.Run("returns false for nil certifier", func(t *testing.T) {
		certifiers := []*ec.PublicKey{tu.GetPKFromString("certifier1")}
		assert.False(t, utils.CertifierInSlice(certifiers, nil))
	})
}

// TestValidateRequestedCertificateSetNil covers the nil-request branch.
func TestValidateRequestedCertificateSetNil(t *testing.T) {
	t.Run("returns error for nil request", func(t *testing.T) {
		err := utils.ValidateRequestedCertificateSet(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "requested certificate set is nil")
	})
}

// TestValidateCertificateCancelledContext covers the early context-cancellation
// branch of the exported ValidateCertificate function.
func TestValidateCertificateCancelledContext(t *testing.T) {
	t.Run("returns context error when context already cancelled", func(t *testing.T) {
		subject, err := ec.NewPrivateKey()
		require.NoError(t, err)
		certifier, err := ec.NewPrivateKey()
		require.NoError(t, err)
		verifier, err := ec.NewPrivateKey()
		require.NoError(t, err)

		cert := tcu.CreateValidCertificate(t, subject, certifier, verifier.PubKey())
		verifierWallet := wallet.NewTestWallet(t, verifier)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err = utils.ValidateCertificate(ctx, verifierWallet, cert, subject.PubKey(), nil)
		require.Error(t, err)
		assert.Equal(t, context.Canceled, err)
	})
}

// TestSignCertificateWithWalletForTestErrors covers the wallet-error branches.
func TestSignCertificateWithWalletForTestErrors(t *testing.T) {
	subject, err := ec.NewPrivateKey()
	require.NoError(t, err)

	cert := wallet.Certificate{
		Type:               tu.GetByte32FromString("some_type"),
		SerialNumber:       tu.GetByte32FromString("some_serial"),
		Subject:            subject.PubKey(),
		RevocationOutpoint: tu.OutpointFromString(t, "a755810c21e17183ff6db6685f0de239fd3a0a3c0d4ba7773b0b0d1748541e2b.0"),
		Fields:             map[string]string{"field1": base64.StdEncoding.EncodeToString([]byte("value"))},
	}

	t.Run("returns error when GetPublicKey fails", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t)
		tw.OnGetPublicKey().ReturnError(errors.New("no identity key"))

		_, err := utils.SignCertificateWithWalletForTest(context.Background(), cert, tw)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get identity key of signer")
	})

	t.Run("returns error when CreateSignature fails", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t)
		tw.OnCreateSignature().ReturnError(errors.New("sign boom"))

		_, err := utils.SignCertificateWithWalletForTest(context.Background(), cert, tw)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign certificate")
	})
}

// TestGetVerifiableCertificatesErrorPaths covers the remaining error/skip branches.
func TestGetVerifiableCertificatesErrorPaths(t *testing.T) {
	ctx := context.Background()

	verifierKey := tu.GetPKFromString("verifier")
	certType1 := tu.GetByte32FromString("certType1")
	certType2 := tu.GetByte32FromString("certType2")
	serial1 := tu.GetByte32FromString("serial1")

	const testSigHex = "3045022100a6f09ee70382ab364f3f6b040aebb8fe7a51dbc3b4c99cfeb2f7756432162833022067349b91a6319345996faddf36d1b2f3a502e4ae002205f9d2db85474f9aed5a"
	testSig := tu.GetSigFromHex(t, testSigHex)

	subject := tu.GetPKFromString("subject")
	certifier := tu.GetPKFromString("certifier")

	requestedCerts := &utils.RequestedCertificateSet{
		Certifiers: []*ec.PublicKey{tu.GetPKFromString("certifier1")},
		CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
			certType1: {"field1"},
		},
	}

	newMatchingCert := func() wallet.CertificateResult {
		return wallet.CertificateResult{
			Certificate: wallet.Certificate{
				Type:               certType1,
				SerialNumber:       serial1,
				Subject:            subject,
				Certifier:          certifier,
				RevocationOutpoint: tu.OutpointFromString(t, "a755810c21e17183ff6db6685f0de239fd3a0a3c0d4ba7773b0b0d1748541e2b.0"),
				Fields:             map[string]string{"field1": base64.StdEncoding.EncodeToString([]byte("v"))},
				Signature:          testSig,
			},
		}
	}

	t.Run("returns error for nil options", func(t *testing.T) {
		certs, err := utils.GetVerifiableCertificates(ctx, nil)
		require.Error(t, err)
		assert.Nil(t, certs)
		require.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("returns error for nil wallet", func(t *testing.T) {
		certs, err := utils.GetVerifiableCertificates(ctx, &utils.GetVerifiableCertificatesOptions{
			Wallet:                nil,
			RequestedCertificates: requestedCerts,
			VerifierIdentityKey:   verifierKey,
		})
		require.Error(t, err)
		assert.Nil(t, certs)
		require.Contains(t, err.Error(), "options.Wallet cannot be nil")
	})

	t.Run("returns error for nil ListCertificates result", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t) //nolint:contextcheck // shared test helper uses context.Background() internally
		tw.OnListCertificates().ReturnSuccess(nil)

		certs, err := utils.GetVerifiableCertificates(ctx, &utils.GetVerifiableCertificatesOptions{
			Wallet:                tw,
			RequestedCertificates: requestedCerts,
			VerifierIdentityKey:   verifierKey,
		})
		require.Error(t, err)
		assert.Nil(t, certs)
		require.Contains(t, err.Error(), "nil result from ListCertificates")
	})

	t.Run("skips certificate with empty type", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t) //nolint:contextcheck // shared test helper uses context.Background() internally
		tw.OnListCertificates().ReturnSuccess(&wallet.ListCertificatesResult{
			Certificates: []wallet.CertificateResult{{Certificate: wallet.Certificate{}}},
		})

		certs, err := utils.GetVerifiableCertificates(ctx, &utils.GetVerifiableCertificatesOptions{
			Wallet:                tw,
			RequestedCertificates: requestedCerts,
			VerifierIdentityKey:   verifierKey,
		})
		require.NoError(t, err)
		assert.Empty(t, certs)
	})

	t.Run("skips certificate whose type was not requested", func(t *testing.T) {
		notRequested := newMatchingCert()
		notRequested.Type = certType2

		tw := wallet.NewTestWalletForRandomKey(t) //nolint:contextcheck // shared test helper uses context.Background() internally
		tw.OnListCertificates().ReturnSuccess(&wallet.ListCertificatesResult{
			Certificates: []wallet.CertificateResult{notRequested},
		})

		certs, err := utils.GetVerifiableCertificates(ctx, &utils.GetVerifiableCertificatesOptions{
			Wallet:                tw,
			RequestedCertificates: requestedCerts,
			VerifierIdentityKey:   verifierKey,
		})
		require.NoError(t, err)
		assert.Empty(t, certs)
	})

	t.Run("propagates ProveCertificate error", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t) //nolint:contextcheck // shared test helper uses context.Background() internally
		tw.OnListCertificates().ReturnSuccess(&wallet.ListCertificatesResult{
			Certificates: []wallet.CertificateResult{newMatchingCert()},
		})
		tw.OnProveCertificate().ReturnError(errors.New("prove boom"))

		certs, err := utils.GetVerifiableCertificates(ctx, &utils.GetVerifiableCertificatesOptions{
			Wallet:                tw,
			RequestedCertificates: requestedCerts,
			VerifierIdentityKey:   verifierKey,
		})
		require.Error(t, err)
		assert.Nil(t, certs)
		require.Contains(t, err.Error(), "prove boom")
	})

	t.Run("returns error for nil ProveCertificate result", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t) //nolint:contextcheck // shared test helper uses context.Background() internally
		tw.OnListCertificates().ReturnSuccess(&wallet.ListCertificatesResult{
			Certificates: []wallet.CertificateResult{newMatchingCert()},
		})
		tw.OnProveCertificate().ReturnSuccess(nil)

		certs, err := utils.GetVerifiableCertificates(ctx, &utils.GetVerifiableCertificatesOptions{
			Wallet:                tw,
			RequestedCertificates: requestedCerts,
			VerifierIdentityKey:   verifierKey,
		})
		require.Error(t, err)
		assert.Nil(t, certs)
		require.Contains(t, err.Error(), "nil result from ProveCertificate")
	})

	t.Run("returns error for keyring value that is not base64", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t) //nolint:contextcheck // shared test helper uses context.Background() internally
		tw.OnListCertificates().ReturnSuccess(&wallet.ListCertificatesResult{
			Certificates: []wallet.CertificateResult{newMatchingCert()},
		})
		tw.OnProveCertificate().ReturnSuccess(&wallet.ProveCertificateResult{
			KeyringForVerifier: map[string]string{"field1": "not valid base64!!!"},
		})

		certs, err := utils.GetVerifiableCertificates(ctx, &utils.GetVerifiableCertificatesOptions{
			Wallet:                tw,
			RequestedCertificates: requestedCerts,
			VerifierIdentityKey:   verifierKey,
		})
		require.Error(t, err)
		assert.Nil(t, certs)
		require.Contains(t, err.Error(), "is not valid base64")
	})

	t.Run("builds verifiable certificate with valid keyring", func(t *testing.T) {
		tw := wallet.NewTestWalletForRandomKey(t) //nolint:contextcheck // shared test helper uses context.Background() internally
		tw.OnListCertificates().ReturnSuccess(&wallet.ListCertificatesResult{
			Certificates: []wallet.CertificateResult{newMatchingCert()},
		})
		tw.OnProveCertificate().ReturnSuccess(&wallet.ProveCertificateResult{
			KeyringForVerifier: map[string]string{"field1": base64.StdEncoding.EncodeToString([]byte("key"))},
		})

		certs, err := utils.GetVerifiableCertificates(ctx, &utils.GetVerifiableCertificatesOptions{
			Wallet:                tw,
			RequestedCertificates: requestedCerts,
			VerifierIdentityKey:   verifierKey,
		})
		require.NoError(t, err)
		require.Len(t, certs, 1)
		assert.Equal(t, wallet.StringBase64FromArray(certType1), certs[0].Type)
	})
}
