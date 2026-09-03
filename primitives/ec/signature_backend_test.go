package primitives

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInjectExternalSignerFn(t *testing.T) {
	InjectExternalSignerFn(nil)
	t.Cleanup(func() { InjectExternalSignerFn(nil) })

	privateKey, err := PrivateKeyFromHex("1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd")
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("external signer"))
	wantSignature, err := privateKey.Sign(digest[:])
	require.NoError(t, err)

	t.Run("uses external signer", func(t *testing.T) {
		called := false
		InjectExternalSignerFn(func(message, privateKeyBytes []byte) ([]byte, error) {
			called = true
			require.Equal(t, digest[:], message)
			require.Equal(t, privateKey.Serialize(), privateKeyBytes)
			return wantSignature.Serialize(), nil
		})

		gotSignature, signErr := privateKey.Sign(digest[:])
		require.NoError(t, signErr)
		require.True(t, wantSignature.IsEqual(gotSignature))
		require.True(t, called)
	})

	t.Run("returns external error", func(t *testing.T) {
		wantErr := errors.New("external signer failure")
		InjectExternalSignerFn(func(_, _ []byte) ([]byte, error) {
			return nil, wantErr
		})

		_, signErr := privateKey.Sign(digest[:])
		require.ErrorIs(t, signErr, wantErr)
	})

	t.Run("rejects malformed signature", func(t *testing.T) {
		InjectExternalSignerFn(func(_, _ []byte) ([]byte, error) {
			return []byte{0x01, 0x02}, nil
		})

		_, signErr := privateKey.Sign(digest[:])
		require.Error(t, signErr)
	})

	t.Run("nil restores built-in signer", func(t *testing.T) {
		InjectExternalSignerFn(nil)
		gotSignature, signErr := privateKey.Sign(digest[:])
		require.NoError(t, signErr)
		require.True(t, wantSignature.IsEqual(gotSignature))
	})
}

func TestInjectExternalVerifySignatureFn(t *testing.T) {
	InjectExternalSignerFn(nil)
	InjectExternalVerifySignatureFn(nil)
	t.Cleanup(func() {
		InjectExternalSignerFn(nil)
		InjectExternalVerifySignatureFn(nil)
	})

	privateKey, err := PrivateKeyFromHex("1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd")
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("external verifier"))
	signature, err := privateKey.Sign(digest[:])
	require.NoError(t, err)

	callCount := 0
	InjectExternalVerifySignatureFn(func(message, signatureBytes, publicKey []byte) bool {
		callCount++
		require.Equal(t, digest[:], message)
		require.Equal(t, signature.Serialize(), signatureBytes)
		require.Equal(t, privateKey.PubKey().Compressed(), publicKey)
		return false
	})

	require.False(t, signature.Verify(digest[:], privateKey.PubKey()))
	require.False(t, Verify(digest[:], signature, privateKey.PubKey().ToECDSA()))
	require.Equal(t, 2, callCount)

	InjectExternalVerifySignatureFn(func(_, _, _ []byte) bool {
		callCount++
		return true
	})
	invalidSignature := &Signature{
		R: new(big.Int).Neg(signature.R),
		S: new(big.Int).Set(signature.S),
	}
	require.False(t, invalidSignature.Verify(digest[:], privateKey.PubKey()))
	require.Equal(t, 2, callCount)

	validPublicKey := privateKey.PubKey()
	invalidPublicKey := &PublicKey{
		Curve: S256(),
		X:     new(big.Int).Set(validPublicKey.X),
		Y:     new(big.Int).Add(validPublicKey.Y, big.NewInt(2)),
	}
	require.False(t, invalidPublicKey.Validate())
	require.Equal(t, validPublicKey.Compressed(), invalidPublicKey.Compressed())
	require.False(t, signature.Verify(digest[:], invalidPublicKey))
	require.Equal(t, 2, callCount, "external verifier must not receive an invalid public key")
	negativePublicKey := &PublicKey{
		Curve: S256(),
		X:     new(big.Int).Set(validPublicKey.X),
		Y:     new(big.Int).Neg(validPublicKey.Y),
	}
	require.Equal(t, validPublicKey.Compressed(), negativePublicKey.Compressed())
	require.False(t, signature.Verify(digest[:], negativePublicKey))
	require.Equal(t, 2, callCount, "external verifier must reject out-of-range coordinates")

	p256PrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p256Digest := sha256.Sum256([]byte("built-in verifier fallback"))
	p256R, p256S, err := ecdsa.Sign(rand.Reader, p256PrivateKey, p256Digest[:])
	require.NoError(t, err)
	p256Signature := &Signature{R: p256R, S: p256S}
	require.True(t, p256Signature.Verify(p256Digest[:], (*PublicKey)(&p256PrivateKey.PublicKey)))
	require.Equal(t, 2, callCount, "external secp256k1 verifier must not receive another curve")

	InjectExternalVerifySignatureFn(nil)
	require.True(t, signature.Verify(digest[:], privateKey.PubKey()))
}
