package compat_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	compat "github.com/bsv-blockchain/go-sdk/compat/bsm"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/stretchr/testify/require"
)

func TestVerifyMessage(t *testing.T) {
	t.Parallel()

	t.Run("verifies a valid compressed message", func(t *testing.T) {
		pk, err := ec.PrivateKeyFromHex("0499f8239bfe10eb0f5e53d543635a423c96529dd85fa4bad42049a0b435ebdd")
		require.NoError(t, err)
		msg := []byte("test message")
		sig, err := compat.SignMessage(pk, msg)
		require.NoError(t, err)

		addr, err := script.NewAddressFromPublicKey(pk.PubKey(), true)
		require.NoError(t, err)

		err = compat.VerifyMessage(addr.AddressString, sig, msg)
		require.NoError(t, err)
	})

	t.Run("fails when address does not match", func(t *testing.T) {
		pk, err := ec.PrivateKeyFromHex("0499f8239bfe10eb0f5e53d543635a423c96529dd85fa4bad42049a0b435ebdd")
		require.NoError(t, err)
		msg := []byte("test message")
		sig, err := compat.SignMessage(pk, msg)
		require.NoError(t, err)

		// Use a different key's address
		pk2, err := ec.PrivateKeyFromHex("ef0b8bad0be285099534277fde328f8f19b3be9cadcd4c08e6ac0b5f863745ac")
		require.NoError(t, err)
		addr2, err := script.NewAddressFromPublicKey(pk2.PubKey(), true)
		require.NoError(t, err)

		err = compat.VerifyMessage(addr2.AddressString, sig, msg)
		require.Error(t, err)
	})

	t.Run("fails with invalid signature bytes", func(t *testing.T) {
		err := compat.VerifyMessage("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf", []byte{0x00, 0x01, 0x02}, []byte("test"))
		require.Error(t, err)
	})

	t.Run("verifies uncompressed key signature", func(t *testing.T) {
		pk, err := ec.PrivateKeyFromHex("0499f8239bfe10eb0f5e53d543635a423c96529dd85fa4bad42049a0b435ebdd")
		require.NoError(t, err)
		msg := []byte("test message")
		sig, err := compat.SignMessageWithCompression(pk, msg, false)
		require.NoError(t, err)

		// VerifyMessage extracts the key from the signature
		pubKey, wasCompressed, err := compat.PubKeyFromSignature(sig, msg)
		require.NoError(t, err)
		require.False(t, wasCompressed)

		addr, err := script.NewAddressFromPublicKeyWithCompression(pubKey, true, wasCompressed)
		require.NoError(t, err)

		err = compat.VerifyMessage(addr.AddressString, sig, msg)
		require.NoError(t, err)
	})
}

func TestVerifyMessageDER(t *testing.T) {
	t.Parallel()

	t.Run("verifies a valid DER signature", func(t *testing.T) {
		pk, err := ec.PrivateKeyFromHex("0499f8239bfe10eb0f5e53d543635a423c96529dd85fa4bad42049a0b435ebdd")
		require.NoError(t, err)

		// Create a hash
		msg := []byte("test message")
		hash := sha256.Sum256(msg)

		// Sign with DER format
		sig, err := pk.Sign(hash[:])
		require.NoError(t, err)
		sigHex := hex.EncodeToString(sig.Serialize())

		pubKeyHex := hex.EncodeToString(pk.PubKey().Compressed())

		verified, err := compat.VerifyMessageDER(hash, pubKeyHex, sigHex)
		require.NoError(t, err)
		require.True(t, verified)
	})

	t.Run("returns false for wrong public key", func(t *testing.T) {
		pk, err := ec.PrivateKeyFromHex("0499f8239bfe10eb0f5e53d543635a423c96529dd85fa4bad42049a0b435ebdd")
		require.NoError(t, err)
		pk2, err := ec.PrivateKeyFromHex("ef0b8bad0be285099534277fde328f8f19b3be9cadcd4c08e6ac0b5f863745ac")
		require.NoError(t, err)

		msg := []byte("test message")
		hash := sha256.Sum256(msg)

		sig, err := pk.Sign(hash[:])
		require.NoError(t, err)
		sigHex := hex.EncodeToString(sig.Serialize())

		// Use wrong public key
		wrongPubKeyHex := hex.EncodeToString(pk2.PubKey().Compressed())
		verified, err := compat.VerifyMessageDER(hash, wrongPubKeyHex, sigHex)
		require.NoError(t, err)
		require.False(t, verified)
	})

	t.Run("returns error for invalid signature hex", func(t *testing.T) {
		hash := sha256.Sum256([]byte("test"))
		pk, err := ec.NewPrivateKey()
		require.NoError(t, err)
		pubKeyHex := hex.EncodeToString(pk.PubKey().Compressed())

		_, err = compat.VerifyMessageDER(hash, pubKeyHex, "not-hex!!")
		require.Error(t, err)
	})

	t.Run("returns error for invalid pubkey hex", func(t *testing.T) {
		pk, err := ec.PrivateKeyFromHex("0499f8239bfe10eb0f5e53d543635a423c96529dd85fa4bad42049a0b435ebdd")
		require.NoError(t, err)
		hash := sha256.Sum256([]byte("test"))
		sig, err := pk.Sign(hash[:])
		require.NoError(t, err)
		sigHex := hex.EncodeToString(sig.Serialize())

		_, err = compat.VerifyMessageDER(hash, "zzzzzzzz", sigHex)
		require.Error(t, err)
	})

	t.Run("returns error for invalid DER signature", func(t *testing.T) {
		pk, err := ec.NewPrivateKey()
		require.NoError(t, err)
		hash := sha256.Sum256([]byte("test"))
		pubKeyHex := hex.EncodeToString(pk.PubKey().Compressed())

		// Valid hex but invalid DER signature
		_, err = compat.VerifyMessageDER(hash, pubKeyHex, "deadbeef")
		require.Error(t, err)
	})
}

func TestPubKeyFromSignature(t *testing.T) {
	t.Parallel()

	t.Run("recovers compressed public key", func(t *testing.T) {
		pk, err := ec.PrivateKeyFromHex("0499f8239bfe10eb0f5e53d543635a423c96529dd85fa4bad42049a0b435ebdd")
		require.NoError(t, err)
		msg := []byte("test message")
		sig, err := compat.SignMessage(pk, msg)
		require.NoError(t, err)

		recoveredKey, wasCompressed, err := compat.PubKeyFromSignature(sig, msg)
		require.NoError(t, err)
		require.True(t, wasCompressed)
		require.True(t, recoveredKey.IsEqual(pk.PubKey()))
	})

	t.Run("recovers uncompressed public key", func(t *testing.T) {
		pk, err := ec.PrivateKeyFromHex("0499f8239bfe10eb0f5e53d543635a423c96529dd85fa4bad42049a0b435ebdd")
		require.NoError(t, err)
		msg := []byte("test message")
		sig, err := compat.SignMessageWithCompression(pk, msg, false)
		require.NoError(t, err)

		recoveredKey, wasCompressed, err := compat.PubKeyFromSignature(sig, msg)
		require.NoError(t, err)
		require.False(t, wasCompressed)
		require.True(t, recoveredKey.IsEqual(pk.PubKey()))
	})

	t.Run("fails with invalid signature", func(t *testing.T) {
		_, _, err := compat.PubKeyFromSignature([]byte{0x00, 0x01, 0x02}, []byte("test"))
		require.Error(t, err)
	})
}
