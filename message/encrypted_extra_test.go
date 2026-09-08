package message

import (
	"testing"

	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// TestDecryptErrors covers the failure branches of BRC-78 Decrypt.
func TestDecryptErrors(t *testing.T) {
	sender, err := ec.NewPrivateKey()
	require.NoError(t, err)
	recipient, err := ec.NewPrivateKey()
	require.NoError(t, err)

	t.Run("message too short", func(t *testing.T) {
		_, err := Decrypt([]byte{0x01, 0x02}, recipient)
		require.ErrorContains(t, err, "message too short")
	})

	t.Run("version mismatch", func(t *testing.T) {
		// Minimum length but all-zero (wrong) version bytes.
		msg := make([]byte, 4+33+33+32+1)
		_, err := Decrypt(msg, recipient)
		require.ErrorContains(t, err, "version mismatch")
	})

	t.Run("invalid sender public key", func(t *testing.T) {
		// Correct version, but the sender public key bytes are not a valid point.
		msg := make([]byte, 4+33+33+32+1)
		copy(msg[:4], []byte{0x42, 0x42, 0x10, 0x33}) // VERSION
		_, err := Decrypt(msg, recipient)
		require.Error(t, err)
	})

	t.Run("wrong recipient", func(t *testing.T) {
		enc, err := Encrypt([]byte("hello world"), sender, recipient.PubKey())
		require.NoError(t, err)

		other, err := ec.NewPrivateKey()
		require.NoError(t, err)
		_, err = Decrypt(enc, other)
		require.ErrorContains(t, err, "recipient public key")
	})

	t.Run("corrupt ciphertext", func(t *testing.T) {
		enc, err := Encrypt([]byte("hello world"), sender, recipient.PubKey())
		require.NoError(t, err)
		enc[len(enc)-1] ^= 0xff // flip a bit in the ciphertext

		_, err = Decrypt(enc, recipient)
		require.Error(t, err)
	})

	t.Run("round trip", func(t *testing.T) {
		plaintext := []byte("the quick brown fox")
		enc, err := Encrypt(plaintext, sender, recipient.PubKey())
		require.NoError(t, err)
		got, err := Decrypt(enc, recipient)
		require.NoError(t, err)
		require.Equal(t, plaintext, got)
	})
}

// TestVerifyVersionMismatch covers the version-mismatch branch of Verify.
func TestVerifyVersionMismatch(t *testing.T) {
	recipient, err := ec.NewPrivateKey()
	require.NoError(t, err)

	// A signature blob long enough to be indexed, but with a wrong version.
	badSig := make([]byte, 4+33+1+32+8)
	_, err = Verify([]byte("msg"), badSig, recipient)
	require.ErrorContains(t, err, "version mismatch")
}
