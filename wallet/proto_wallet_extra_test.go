package wallet_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func newRealProto(t *testing.T) *wallet.ProtoWallet {
	t.Helper()
	pk, err := ec.NewPrivateKey()
	require.NoError(t, err)
	w, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{
		Type:       wallet.ProtoWalletArgsTypePrivateKey,
		PrivateKey: pk,
	})
	require.NoError(t, err)
	return w
}

// newNilKeyDeriverProto returns a ProtoWallet whose keyDeriver is nil, so every
// crypto method returns "keyDeriver is undefined".
func newNilKeyDeriverProto(t *testing.T) *wallet.ProtoWallet {
	t.Helper()
	w, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{
		Type:       wallet.ProtoWalletArgsTypeKeyDeriver,
		KeyDeriver: nil,
	})
	require.NoError(t, err)
	return w
}

func validProtocol() wallet.Protocol {
	return wallet.Protocol{SecurityLevel: wallet.SecurityLevelSilent, Protocol: "testprotocol"}
}

// badProtocol has a protocol name that is too short, so computeInvoiceNumber fails.
func badProtocol() wallet.Protocol {
	return wallet.Protocol{SecurityLevel: wallet.SecurityLevelSilent, Protocol: "ab"}
}

func TestNewProtoWalletVariants(t *testing.T) {
	t.Parallel()

	t.Run("anyone", func(t *testing.T) {
		t.Parallel()
		w, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{Type: wallet.ProtoWalletArgsTypeAnyone})
		require.NoError(t, err)
		require.NotNil(t, w)
	})

	t.Run("keyDeriver", func(t *testing.T) {
		t.Parallel()
		pk, err := ec.NewPrivateKey()
		require.NoError(t, err)
		w, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{
			Type:       wallet.ProtoWalletArgsTypeKeyDeriver,
			KeyDeriver: wallet.NewKeyDeriver(pk),
		})
		require.NoError(t, err)
		require.NotNil(t, w)
	})

	t.Run("invalid type", func(t *testing.T) {
		t.Parallel()
		_, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{Type: wallet.ProtoWalletArgsType("bogus")})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid rootKeyOrKeyDeriver")
	})
}

func TestProtoWalletNilKeyDeriver(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newNilKeyDeriverProto(t)

	const wantErr = "keyDeriver is undefined"

	t.Run("GetPublicKey identity", func(t *testing.T) {
		t.Parallel()
		_, err := w.GetPublicKey(ctx, wallet.GetPublicKeyArgs{IdentityKey: true}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), wantErr)
	})

	t.Run("GetPublicKey derived", func(t *testing.T) {
		t.Parallel()
		_, err := w.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
			EncryptionArgs: wallet.EncryptionArgs{ProtocolID: validProtocol(), KeyID: "k1"},
		}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), wantErr)
	})

	t.Run("Encrypt", func(t *testing.T) {
		t.Parallel()
		_, err := w.Encrypt(ctx, wallet.EncryptArgs{
			EncryptionArgs: wallet.EncryptionArgs{ProtocolID: validProtocol(), KeyID: "k1"},
			Plaintext:      []byte("x"),
		}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), wantErr)
	})

	t.Run("Decrypt", func(t *testing.T) {
		t.Parallel()
		_, err := w.Decrypt(ctx, wallet.DecryptArgs{
			EncryptionArgs: wallet.EncryptionArgs{ProtocolID: validProtocol(), KeyID: "k1"},
			Ciphertext:     []byte("x"),
		}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), wantErr)
	})

	t.Run("CreateSignature", func(t *testing.T) {
		t.Parallel()
		_, err := w.CreateSignature(ctx, wallet.CreateSignatureArgs{
			EncryptionArgs: wallet.EncryptionArgs{ProtocolID: validProtocol(), KeyID: "k1"},
			Data:           []byte("x"),
		}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), wantErr)
	})

	t.Run("VerifySignature", func(t *testing.T) {
		t.Parallel()
		_, err := w.VerifySignature(ctx, wallet.VerifySignatureArgs{
			EncryptionArgs: wallet.EncryptionArgs{ProtocolID: validProtocol(), KeyID: "k1"},
			Data:           []byte("x"),
		}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), wantErr)
	})

	t.Run("CreateHMAC", func(t *testing.T) {
		t.Parallel()
		_, err := w.CreateHMAC(ctx, wallet.CreateHMACArgs{
			EncryptionArgs: wallet.EncryptionArgs{ProtocolID: validProtocol(), KeyID: "k1"},
			Data:           []byte("x"),
		}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), wantErr)
	})

	t.Run("VerifyHMAC", func(t *testing.T) {
		t.Parallel()
		_, err := w.VerifyHMAC(ctx, wallet.VerifyHMACArgs{
			EncryptionArgs: wallet.EncryptionArgs{ProtocolID: validProtocol(), KeyID: "k1"},
			Data:           []byte("x"),
		}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), wantErr)
	})
}

func TestProtoWalletGetPublicKeyValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newRealProto(t)

	t.Run("missing protocolID and keyID", func(t *testing.T) {
		t.Parallel()
		_, err := w.GetPublicKey(ctx, wallet.GetPublicKeyArgs{}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "protocolID and keyID are required")
	})

	t.Run("derive failure", func(t *testing.T) {
		t.Parallel()
		_, err := w.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
			EncryptionArgs: wallet.EncryptionArgs{ProtocolID: badProtocol(), KeyID: "k1"},
		}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to derive public key")
	})
}

func TestProtoWalletDeriveErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newRealProto(t)

	t.Run("Encrypt derive failure", func(t *testing.T) {
		t.Parallel()
		_, err := w.Encrypt(ctx, wallet.EncryptArgs{
			EncryptionArgs: wallet.EncryptionArgs{ProtocolID: badProtocol(), KeyID: "k1"},
			Plaintext:      []byte("x"),
		}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to derive symmetric key")
	})

	t.Run("Decrypt derive failure", func(t *testing.T) {
		t.Parallel()
		_, err := w.Decrypt(ctx, wallet.DecryptArgs{
			EncryptionArgs: wallet.EncryptionArgs{ProtocolID: badProtocol(), KeyID: "k1"},
			Ciphertext:     []byte("x"),
		}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to derive symmetric key")
	})

	t.Run("CreateSignature derive failure", func(t *testing.T) {
		t.Parallel()
		_, err := w.CreateSignature(ctx, wallet.CreateSignatureArgs{
			EncryptionArgs: wallet.EncryptionArgs{ProtocolID: badProtocol(), KeyID: "k1"},
			Data:           []byte("x"),
		}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to derive private key")
	})

	t.Run("CreateHMAC derive failure", func(t *testing.T) {
		t.Parallel()
		_, err := w.CreateHMAC(ctx, wallet.CreateHMACArgs{
			EncryptionArgs: wallet.EncryptionArgs{ProtocolID: badProtocol(), KeyID: "k1"},
			Data:           []byte("x"),
		}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to derive symmetric key")
	})

	t.Run("VerifyHMAC derive failure", func(t *testing.T) {
		t.Parallel()
		_, err := w.VerifyHMAC(ctx, wallet.VerifyHMACArgs{
			EncryptionArgs: wallet.EncryptionArgs{ProtocolID: badProtocol(), KeyID: "k1"},
			Data:           []byte("x"),
		}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to derive symmetric key")
	})
}

func TestProtoWalletVerifySignatureBranches(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newRealProto(t)

	t.Run("no data and no hash", func(t *testing.T) {
		t.Parallel()
		_, err := w.VerifySignature(ctx, wallet.VerifySignatureArgs{
			EncryptionArgs: wallet.EncryptionArgs{ProtocolID: validProtocol(), KeyID: "k1"},
		}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be valid")
	})

	t.Run("derive failure", func(t *testing.T) {
		t.Parallel()
		_, err := w.VerifySignature(ctx, wallet.VerifySignatureArgs{
			EncryptionArgs: wallet.EncryptionArgs{ProtocolID: badProtocol(), KeyID: "k1"},
			Data:           []byte("x"),
		}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to derive public key")
	})

	t.Run("nil signature", func(t *testing.T) {
		t.Parallel()
		_, err := w.VerifySignature(ctx, wallet.VerifySignatureArgs{
			EncryptionArgs: wallet.EncryptionArgs{ProtocolID: validProtocol(), KeyID: "k1"},
			Data:           []byte("x"),
			Signature:      nil,
		}, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signature is nil")
	})
}
