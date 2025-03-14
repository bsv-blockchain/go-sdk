package message

import (
	"crypto/rand"
	"math/big"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/require"
	// Using testify for assertions similar to JavaScript's expect
)

func TestSignedMessage(t *testing.T) {
	t.Run("Signs a message for a recipient", func(t *testing.T) {
		senderPriv, _ := ec.PrivateKeyFromBytes([]byte{15})
		recipientPriv, recipientPub := ec.PrivateKeyFromBytes([]byte{21})

		message := []byte{1, 2, 4, 8, 16, 32}
		signature, err := Sign(message, senderPriv, recipientPub)
		require.NoError(t, err)

		verified, err := Verify(message, signature, recipientPriv)
		require.NoError(t, err)
		require.True(t, verified)
	})

	t.Run("Signs a message for anyone", func(t *testing.T) {
		senderPriv, _ := ec.PrivateKeyFromBytes([]byte{15})

		message := []byte{1, 2, 4, 8, 16, 32}
		signature, err := Sign(message, senderPriv, nil)
		require.NoError(t, err)

		verified, err := Verify(message, signature, nil)
		require.NoError(t, err)
		require.True(t, verified)
	})

	t.Run("Fails to verify a message with a wrong version", func(t *testing.T) {
		senderPriv, _ := ec.PrivateKeyFromBytes([]byte{15})
		recipientPriv, recipientPub := ec.PrivateKeyFromBytes([]byte{21})

		message := []byte{1, 2, 4, 8, 16, 32}
		signature, _ := Sign(message, senderPriv, recipientPub)
		signature[0] = 1 // Alter the signature to simulate version mismatch

		_, err := Verify(message, signature, recipientPriv)
		require.Error(t, err)
		require.Equal(t, "message version mismatch: Expected 42423301, received 01423301", err.Error())
	})

}

func TestEdgeCases(t *testing.T) {
	signingPriv, _ := ec.PrivateKeyFromBytes([]byte{15})

	message := make([]byte, 32)
	for i := 0; i < 10000; i++ {
		_, _ = rand.Read(message)
		signature, err := signingPriv.Sign(message)
		require.NoError(t, err)

		// Manually set R and S to edge case values (e.g., highest bit set).
		// These values will require padding when encoded in DER.
		signature.R = big.NewInt(0x80)                                      // Example: 128, which in binary is 10000000
		signature.S = new(big.Int).SetBytes([]byte{0x80, 0x00, 0x00, 0x01}) // Example edge case

		signatureSerialized := signature.Serialize()
		signatureDER, err := signature.ToDER()
		require.NoError(t, err)

		require.Equal(t, signatureSerialized, signatureDER)
		require.Equal(t, len(signatureSerialized), len(signatureDER))
		t.Logf("Signature serialized: %d %x - %d %x\n", len(signatureDER), signatureDER, len(signatureSerialized), signatureSerialized)
	}
}
