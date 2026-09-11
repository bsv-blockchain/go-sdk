package wallet_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func TestNewWalletVariants(t *testing.T) {
	t.Parallel()

	t.Run("nil private key produces anyone wallet", func(t *testing.T) {
		t.Parallel()
		w, err := wallet.NewWallet(nil)
		require.NoError(t, err)
		require.NotNil(t, w)
	})

	t.Run("valid private key", func(t *testing.T) {
		t.Parallel()
		pk, err := ec.NewPrivateKey()
		require.NoError(t, err)
		w, err := wallet.NewWallet(pk)
		require.NoError(t, err)
		require.NotNil(t, w)
	})
}

func TestCertificateTypeFromBase64TooLong(t *testing.T) {
	t.Parallel()
	// 33 bytes base64-encoded exceeds the 32-byte certificate type limit.
	tooLong := base64.StdEncoding.EncodeToString(make([]byte, 33))
	_, err := wallet.CertificateTypeFromBase64(tooLong)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "longer then 32 bytes")
}

func TestToIdentityKeyFromPrivateKey(t *testing.T) {
	t.Parallel()
	privBytes := make([]byte, 32)
	for i := range privBytes {
		privBytes[i] = byte(i + 1)
	}
	pk, _ := ec.PrivateKeyFromBytes(privBytes)

	t.Run("valid PrivHex", func(t *testing.T) {
		t.Parallel()
		pub, err := wallet.ToIdentityKey(wallet.PrivHex(hex.EncodeToString(privBytes)))
		require.NoError(t, err)
		assert.Equal(t, pk.PubKey(), pub)
	})

	t.Run("valid *ec.PrivateKey", func(t *testing.T) {
		t.Parallel()
		pub, err := wallet.ToIdentityKey(pk)
		require.NoError(t, err)
		assert.Equal(t, pk.PubKey(), pub)
	})

	t.Run("nil *ec.PrivateKey", func(t *testing.T) {
		t.Parallel()
		var nilPK *ec.PrivateKey
		_, err := wallet.ToIdentityKey(nilPK)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "private key cannot be nil to produce identity key")
	})
}

func TestCompletedProtoWalletVerifySignature(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pk, err := ec.NewPrivateKey()
	require.NoError(t, err)
	w, err := wallet.NewCompletedProtoWallet(pk)
	require.NoError(t, err)

	encArgs := wallet.EncryptionArgs{
		ProtocolID:   wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "testprotocol"},
		KeyID:        "k1",
		Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
	}
	data := []byte("message to sign")

	created, err := w.CreateSignature(ctx, wallet.CreateSignatureArgs{
		EncryptionArgs: encArgs,
		Data:           data,
	}, "app")
	require.NoError(t, err)

	verified, err := w.VerifySignature(ctx, wallet.VerifySignatureArgs{
		EncryptionArgs: encArgs,
		Data:           data,
		Signature:      created.Signature,
	}, "app")
	require.NoError(t, err)
	assert.True(t, verified.Valid)
}
