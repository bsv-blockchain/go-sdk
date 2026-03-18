package wallet_test

import (
	"context"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCompletedProtoWallet(t *testing.T) *wallet.CompletedProtoWallet {
	t.Helper()
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	w, err := wallet.NewCompletedProtoWallet(privKey)
	require.NoError(t, err)
	return w
}

func TestNewCompletedProtoWallet(t *testing.T) {
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	w, err := wallet.NewCompletedProtoWallet(privKey)
	require.NoError(t, err)
	assert.NotNil(t, w)
}

func TestCompletedProtoWalletCreateAction(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	result, err := w.CreateAction(context.Background(), wallet.CreateActionArgs{
		Description: "test",
	}, "test")
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestCompletedProtoWalletAbortAction(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	_, err := w.AbortAction(context.Background(), wallet.AbortActionArgs{
		Reference: []byte("ref"),
	}, "test")
	// Returns nil,nil by design
	assert.NoError(t, err)
}

func TestCompletedProtoWalletListCertificates(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	result, err := w.ListCertificates(context.Background(), wallet.ListCertificatesArgs{}, "test")
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, uint32(0), result.TotalCertificates)
}

func TestCompletedProtoWalletProveCertificate(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	result, err := w.ProveCertificate(context.Background(), wallet.ProveCertificateArgs{}, "test")
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestCompletedProtoWalletAcquireCertificate(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	result, err := w.AcquireCertificate(context.Background(), wallet.AcquireCertificateArgs{}, "test")
	// Returns nil,nil by design
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestCompletedProtoWalletIsAuthenticated(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	result, err := w.IsAuthenticated(context.Background(), nil, "test")
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Authenticated)
}

func TestCompletedProtoWalletGetHeight(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	result, err := w.GetHeight(context.Background(), nil, "test")
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, uint32(0), result.Height)
}

func TestCompletedProtoWalletGetNetwork(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	result, err := w.GetNetwork(context.Background(), nil, "test")
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, wallet.NetworkTestnet, result.Network)
}

func TestCompletedProtoWalletGetVersion(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	result, err := w.GetVersion(context.Background(), nil, "test")
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.Version)
}

func TestCompletedProtoWalletSignAction(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	result, err := w.SignAction(context.Background(), wallet.SignActionArgs{}, "test")
	// Returns nil,nil by design
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestCompletedProtoWalletListActions(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	result, err := w.ListActions(context.Background(), wallet.ListActionsArgs{}, "test")
	// Returns nil,nil by design
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestCompletedProtoWalletInternalizeAction(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	result, err := w.InternalizeAction(context.Background(), wallet.InternalizeActionArgs{}, "test")
	// Returns nil,nil by design
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestCompletedProtoWalletListOutputs(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	result, err := w.ListOutputs(context.Background(), wallet.ListOutputsArgs{}, "test")
	// Returns nil,nil by design
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestCompletedProtoWalletRelinquishOutput(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	result, err := w.RelinquishOutput(context.Background(), wallet.RelinquishOutputArgs{}, "test")
	// Returns nil,nil by design
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestCompletedProtoWalletRelinquishCertificate(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	result, err := w.RelinquishCertificate(context.Background(), wallet.RelinquishCertificateArgs{}, "test")
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestCompletedProtoWalletDiscoverByIdentityKey(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	result, err := w.DiscoverByIdentityKey(context.Background(), wallet.DiscoverByIdentityKeyArgs{}, "test")
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestCompletedProtoWalletDiscoverByAttributes(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	result, err := w.DiscoverByAttributes(context.Background(), wallet.DiscoverByAttributesArgs{}, "test")
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestCompletedProtoWalletWaitForAuthentication(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	result, err := w.WaitForAuthentication(context.Background(), nil, "test")
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestCompletedProtoWalletGetHeaderForHeight(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	result, err := w.GetHeaderForHeight(context.Background(), wallet.GetHeaderArgs{Height: 100}, "test")
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestCompletedProtoWalletCreateHMAC(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	result, err := w.CreateHMAC(context.Background(), wallet.CreateHMACArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "testprotocol",
			},
			KeyID: "key1",
		},
		Data: []byte("test data"),
	}, "test")
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestCompletedProtoWalletVerifyHMAC(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	ctx := context.Background()

	// Create first
	createResult, err := w.CreateHMAC(ctx, wallet.CreateHMACArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "testprotocol",
			},
			KeyID: "key1",
		},
		Data: []byte("test data"),
	}, "test")
	require.NoError(t, err)

	// Verify
	verifyResult, err := w.VerifyHMAC(ctx, wallet.VerifyHMACArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "testprotocol",
			},
			KeyID: "key1",
		},
		Data: []byte("test data"),
		HMAC: createResult.HMAC,
	}, "test")
	require.NoError(t, err)
	assert.True(t, verifyResult.Valid)
}

func TestCompletedProtoWalletCreateSignature(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	result, err := w.CreateSignature(context.Background(), wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "testprotocol",
			},
			KeyID: "key1",
		},
		Data: []byte("test data"),
	}, "test")
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestCompletedProtoWalletEncryptDecrypt(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	ctx := context.Background()

	plaintext := []byte("hello, encrypted world")
	encryptResult, err := w.Encrypt(ctx, wallet.EncryptArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "testprotocol",
			},
			KeyID: "key1",
		},
		Plaintext: plaintext,
	}, "test")
	require.NoError(t, err)
	assert.NotNil(t, encryptResult)

	decryptResult, err := w.Decrypt(ctx, wallet.DecryptArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryApp,
				Protocol:      "testprotocol",
			},
			KeyID: "key1",
		},
		Ciphertext: encryptResult.Ciphertext,
	}, "test")
	require.NoError(t, err)
	assert.Equal(t, plaintext, []byte(decryptResult.Plaintext))
}

func TestCompletedProtoWalletRevealCounterpartyKeyLinkage(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	ctx := context.Background()

	verifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	counterpartyKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	result, err := w.RevealCounterpartyKeyLinkage(ctx, wallet.RevealCounterpartyKeyLinkageArgs{
		Counterparty: counterpartyKey.PubKey(),
		Verifier:     verifierKey.PubKey(),
	}, "test")
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.EncryptedLinkage)
}

func TestCompletedProtoWalletRevealSpecificKeyLinkage(t *testing.T) {
	w := newTestCompletedProtoWallet(t)
	ctx := context.Background()

	verifierKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	counterpartyKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	result, err := w.RevealSpecificKeyLinkage(ctx, wallet.RevealSpecificKeyLinkageArgs{
		Counterparty: wallet.Counterparty{
			Type:         wallet.CounterpartyTypeOther,
			Counterparty: counterpartyKey.PubKey(),
		},
		Verifier: verifierKey.PubKey(),
		ProtocolID: wallet.Protocol{
			SecurityLevel: wallet.SecurityLevelEveryApp,
			Protocol:      "testprotocol",
		},
		KeyID: "key1",
	}, "test")
	require.NoError(t, err)
	assert.NotNil(t, result)
}
