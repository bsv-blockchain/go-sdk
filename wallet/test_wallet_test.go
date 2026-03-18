package wallet_test

import (
	"context"
	"errors"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testKeyID = "test-key"
	testAppID = "my-app"
)


func TestNewTestWalletForRandomKey(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	assert.NotNil(t, tw)
	assert.NotEmpty(t, tw.Name)
}

func TestNewTestWallet(t *testing.T) {
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	tw := wallet.NewTestWallet(t, privKey)
	assert.NotNil(t, tw)
}

func TestTestWalletGetPublicKey(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	result, err := tw.GetPublicKey(ctx, wallet.GetPublicKeyArgs{IdentityKey: true}, "test")
	require.NoError(t, err)
	assert.NotNil(t, result.PublicKey)
}

func TestTestWalletGetPublicKeyOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	privKey, _ := ec.NewPrivateKey()
	expectedKey := privKey.PubKey()

	tw.OnGetPublicKey().ReturnSuccess(&wallet.GetPublicKeyResult{
		PublicKey: expectedKey,
	})

	result, err := tw.GetPublicKey(ctx, wallet.GetPublicKeyArgs{IdentityKey: true}, "test")
	require.NoError(t, err)
	assert.Equal(t, expectedKey, result.PublicKey)
}

func TestTestWalletGetPublicKeyError(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnGetPublicKey().ReturnError(errors.New("test error"))

	_, err := tw.GetPublicKey(ctx, wallet.GetPublicKeyArgs{IdentityKey: true}, "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "test error")
}

func TestTestWalletEncryptDecrypt(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	plaintext := []byte("secret message")
	encArgs := wallet.EncryptArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "testprotocol",
			},
			KeyID: "k1",
		},
		Plaintext: plaintext,
	}

	encResult, err := tw.Encrypt(ctx, encArgs, "test")
	require.NoError(t, err)

	decResult, err := tw.Decrypt(ctx, wallet.DecryptArgs{
		EncryptionArgs: encArgs.EncryptionArgs,
		Ciphertext:     encResult.Ciphertext,
	}, "test")
	require.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decResult.Plaintext))
}

func TestTestWalletEncryptOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	expectedCiphertext := wallet.BytesList{1, 2, 3}
	tw.OnEncrypt().ReturnSuccess(&wallet.EncryptResult{Ciphertext: expectedCiphertext})

	result, err := tw.Encrypt(ctx, wallet.EncryptArgs{}, "test")
	require.NoError(t, err)
	assert.Equal(t, expectedCiphertext, result.Ciphertext)
}

func TestTestWalletDecryptOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	expectedPlaintext := wallet.BytesList{4, 5, 6}
	tw.OnDecrypt().ReturnSuccess(&wallet.DecryptResult{Plaintext: expectedPlaintext})

	result, err := tw.Decrypt(ctx, wallet.DecryptArgs{}, "test")
	require.NoError(t, err)
	assert.Equal(t, expectedPlaintext, result.Plaintext)
}

func TestTestWalletCreateHMACOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	expectedHMAC := [32]byte{1, 2, 3}
	tw.OnCreateHMAC().ReturnSuccess(&wallet.CreateHMACResult{HMAC: expectedHMAC})

	result, err := tw.CreateHMAC(ctx, wallet.CreateHMACArgs{}, "test")
	require.NoError(t, err)
	assert.Equal(t, expectedHMAC, result.HMAC)
}

func TestTestWalletVerifyHMACOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnVerifyHMAC().ReturnSuccess(&wallet.VerifyHMACResult{Valid: true})

	result, err := tw.VerifyHMAC(ctx, wallet.VerifyHMACArgs{}, "test")
	require.NoError(t, err)
	assert.True(t, result.Valid)
}

func TestTestWalletCreateSignatureOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	privKey, _ := ec.NewPrivateKey()
	hash := make([]byte, 32)
	sig, _ := privKey.Sign(hash)

	tw.OnCreateSignature().ReturnSuccess(&wallet.CreateSignatureResult{Signature: sig})

	result, err := tw.CreateSignature(ctx, wallet.CreateSignatureArgs{}, "test")
	require.NoError(t, err)
	assert.NotNil(t, result.Signature)
}

func TestTestWalletVerifySignatureOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnVerifySignature().ReturnSuccess(&wallet.VerifySignatureResult{Valid: true})

	privKey, _ := ec.NewPrivateKey()
	hash := make([]byte, 32)
	sig, _ := privKey.Sign(hash)

	result, err := tw.VerifySignature(ctx, wallet.VerifySignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "testprotocol",
			},
			KeyID: "k1",
		},
		Signature: sig,
		Data:      []byte("test"),
	}, "test")
	require.NoError(t, err)
	assert.True(t, result.Valid)
}

func TestTestWalletCreateActionOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{})

	result, err := tw.CreateAction(ctx, wallet.CreateActionArgs{Description: "test"}, "test")
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestTestWalletSignActionOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnSignAction().ReturnSuccess(&wallet.SignActionResult{})

	result, err := tw.SignAction(ctx, wallet.SignActionArgs{}, "test")
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestTestWalletAbortActionOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnAbortAction().ReturnSuccess(&wallet.AbortActionResult{Aborted: true})

	result, err := tw.AbortAction(ctx, wallet.AbortActionArgs{}, "test")
	require.NoError(t, err)
	assert.True(t, result.Aborted)
}

func TestTestWalletListActionsOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnListActions().ReturnSuccess(&wallet.ListActionsResult{TotalActions: 5})

	result, err := tw.ListActions(ctx, wallet.ListActionsArgs{}, "test")
	require.NoError(t, err)
	assert.Equal(t, uint32(5), result.TotalActions)
}

func TestTestWalletInternalizeActionOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnInternalizeAction().ReturnSuccess(&wallet.InternalizeActionResult{Accepted: true})

	result, err := tw.InternalizeAction(ctx, wallet.InternalizeActionArgs{}, "test")
	require.NoError(t, err)
	assert.True(t, result.Accepted)
}

func TestTestWalletListOutputsOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{TotalOutputs: 3})

	result, err := tw.ListOutputs(ctx, wallet.ListOutputsArgs{}, "test")
	require.NoError(t, err)
	assert.Equal(t, uint32(3), result.TotalOutputs)
}

func TestTestWalletRelinquishOutputOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnRelinquishOutput().ReturnSuccess(&wallet.RelinquishOutputResult{Relinquished: true})

	result, err := tw.RelinquishOutput(ctx, wallet.RelinquishOutputArgs{}, "test")
	require.NoError(t, err)
	assert.True(t, result.Relinquished)
}

func TestTestWalletRevealCounterpartyKeyLinkageOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnRevealCounterpartyKeyLinkage().ReturnSuccess(&wallet.RevealCounterpartyKeyLinkageResult{
		RevelationTime: "2024-01-01T00:00:00Z",
	})

	privKey, _ := ec.NewPrivateKey()
	result, err := tw.RevealCounterpartyKeyLinkage(ctx, wallet.RevealCounterpartyKeyLinkageArgs{
		Counterparty: privKey.PubKey(),
		Verifier:     privKey.PubKey(),
	}, "test")
	require.NoError(t, err)
	assert.Equal(t, "2024-01-01T00:00:00Z", result.RevelationTime)
}

func TestTestWalletRevealSpecificKeyLinkageOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnRevealSpecificKeyLinkage().ReturnSuccess(&wallet.RevealSpecificKeyLinkageResult{
		KeyID: testKeyID,
	})

	privKey, _ := ec.NewPrivateKey()
	result, err := tw.RevealSpecificKeyLinkage(ctx, wallet.RevealSpecificKeyLinkageArgs{
		Verifier: privKey.PubKey(),
		Counterparty: wallet.Counterparty{
			Type:         wallet.CounterpartyTypeOther,
			Counterparty: privKey.PubKey(),
		},
		ProtocolID: wallet.Protocol{SecurityLevel: 0, Protocol: "testprotocol"},
		KeyID:      testKeyID,
	}, "test")
	require.NoError(t, err)
	assert.Equal(t, testKeyID, result.KeyID)
}

func TestTestWalletAcquireCertificateOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	privKey, _ := ec.NewPrivateKey()
	ct, _ := wallet.CertificateTypeFromString("testcert")
	expectedCert := &wallet.Certificate{
		Type:    ct,
		Subject: privKey.PubKey(),
	}
	tw.OnAcquireCertificate().ReturnSuccess(expectedCert)

	result, err := tw.AcquireCertificate(ctx, wallet.AcquireCertificateArgs{}, "test")
	require.NoError(t, err)
	assert.Equal(t, expectedCert, result)
}

func TestTestWalletListCertificatesOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnListCertificates().ReturnSuccess(&wallet.ListCertificatesResult{TotalCertificates: 2})

	result, err := tw.ListCertificates(ctx, wallet.ListCertificatesArgs{}, "test")
	require.NoError(t, err)
	assert.Equal(t, uint32(2), result.TotalCertificates)
}

func TestTestWalletProveCertificateOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnProveCertificate().ReturnSuccess(&wallet.ProveCertificateResult{
		KeyringForVerifier: map[string]string{"field": "value"},
	})

	result, err := tw.ProveCertificate(ctx, wallet.ProveCertificateArgs{}, "test")
	require.NoError(t, err)
	assert.NotNil(t, result.KeyringForVerifier)
}

func TestTestWalletRelinquishCertificateOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnRelinquishCertificate().ReturnSuccess(&wallet.RelinquishCertificateResult{Relinquished: true})

	result, err := tw.RelinquishCertificate(ctx, wallet.RelinquishCertificateArgs{}, "test")
	require.NoError(t, err)
	assert.True(t, result.Relinquished)
}

func TestTestWalletDiscoverByIdentityKeyOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnDiscoverByIdentityKey().ReturnSuccess(&wallet.DiscoverCertificatesResult{TotalCertificates: 1})

	privKey, _ := ec.NewPrivateKey()
	result, err := tw.DiscoverByIdentityKey(ctx, wallet.DiscoverByIdentityKeyArgs{
		IdentityKey: privKey.PubKey(),
	}, "test")
	require.NoError(t, err)
	assert.Equal(t, uint32(1), result.TotalCertificates)
}

func TestTestWalletDiscoverByAttributesOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnDiscoverByAttributes().ReturnSuccess(&wallet.DiscoverCertificatesResult{TotalCertificates: 3})

	result, err := tw.DiscoverByAttributes(ctx, wallet.DiscoverByAttributesArgs{}, "test")
	require.NoError(t, err)
	assert.Equal(t, uint32(3), result.TotalCertificates)
}

func TestTestWalletIsAuthenticatedOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnIsAuthenticated().ReturnSuccess(&wallet.AuthenticatedResult{Authenticated: true})

	result, err := tw.IsAuthenticated(ctx, nil, "test")
	require.NoError(t, err)
	assert.True(t, result.Authenticated)
}

func TestTestWalletWaitForAuthenticationOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnWaitForAuthentication().ReturnSuccess(&wallet.AuthenticatedResult{Authenticated: true})

	result, err := tw.WaitForAuthentication(ctx, nil, "test")
	require.NoError(t, err)
	assert.True(t, result.Authenticated)
}

func TestTestWalletGetHeightOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnGetHeight().ReturnSuccess(&wallet.GetHeightResult{Height: 100})

	result, err := tw.GetHeight(ctx, nil, "test")
	require.NoError(t, err)
	assert.Equal(t, uint32(100), result.Height)
}

func TestTestWalletGetHeaderForHeightOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnGetHeaderForHeight().ReturnSuccess(&wallet.GetHeaderResult{Header: []byte{0x01}})

	result, err := tw.GetHeaderForHeight(ctx, wallet.GetHeaderArgs{Height: 50}, "test")
	require.NoError(t, err)
	assert.Equal(t, []byte{0x01}, result.Header)
}

func TestTestWalletGetNetworkOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnGetNetwork().ReturnSuccess(&wallet.GetNetworkResult{Network: wallet.NetworkMainnet})

	result, err := tw.GetNetwork(ctx, nil, "test")
	require.NoError(t, err)
	assert.Equal(t, wallet.NetworkMainnet, result.Network)
}

func TestTestWalletGetVersionOverride(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.OnGetVersion().ReturnSuccess(&wallet.GetVersionResult{Version: "2.0.0"})

	result, err := tw.GetVersion(ctx, nil, "test")
	require.NoError(t, err)
	assert.Equal(t, "2.0.0", result.Version)
}

func TestTestWalletExpectOriginator(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	tw.ExpectOriginator("expected-originator")

	// Call with expected originator - should work without panic
	_, err := tw.GetPublicKey(ctx, wallet.GetPublicKeyArgs{IdentityKey: true}, "expected-originator")
	require.NoError(t, err)
}

func TestTestWalletMockDo(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	callCount := 0
	tw.OnGetPublicKey().Do(func(ctx context.Context, args wallet.GetPublicKeyArgs, originator string) (*wallet.GetPublicKeyResult, error) {
		callCount++
		privKey, _ := ec.NewPrivateKey()
		return &wallet.GetPublicKeyResult{PublicKey: privKey.PubKey()}, nil
	})

	_, err := tw.GetPublicKey(ctx, wallet.GetPublicKeyArgs{}, "test")
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Reset returns to default behavior
	tw.OnGetPublicKey().Reset()
	_, err = tw.GetPublicKey(ctx, wallet.GetPublicKeyArgs{IdentityKey: true}, "test")
	require.NoError(t, err)
}

func TestTestWalletExpect(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	gotOriginator := ""
	tw.OnGetPublicKey().
		Expect(func(ctx context.Context, args wallet.GetPublicKeyArgs, originator string) {
			gotOriginator = originator
		}).
		ReturnSuccess(&wallet.GetPublicKeyResult{})

	_, err := tw.GetPublicKey(ctx, wallet.GetPublicKeyArgs{}, testAppID)
	require.NoError(t, err)
	assert.Equal(t, testAppID, gotOriginator)
}

func TestTestWalletExpectOriginatorMethod(t *testing.T) {
	tw := wallet.NewTestWalletForRandomKey(t)
	ctx := context.Background()

	// ExpectOriginator on MockWalletMethods
	privKey, _ := ec.NewPrivateKey()
	tw.OnGetPublicKey().
		ExpectOriginator(testAppID).
		ReturnSuccess(&wallet.GetPublicKeyResult{PublicKey: privKey.PubKey()})

	result, err := tw.GetPublicKey(ctx, wallet.GetPublicKeyArgs{}, testAppID)
	require.NoError(t, err)
	assert.NotNil(t, result)
}
