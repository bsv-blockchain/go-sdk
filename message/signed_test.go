package message

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/v2/primitives/ec"
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

	t.Run("Fails to verify a message with no verifier when required", func(t *testing.T) {
		senderPriv, _ := ec.PrivateKeyFromBytes([]byte{15})
		_, recipientPub := ec.PrivateKeyFromBytes([]byte{21}) // Specific recipient

		message := []byte{1, 2, 4, 8, 16, 32}
		signature, err := Sign(message, senderPriv, recipientPub)
		require.NoError(t, err)

		verified, err := Verify(message, signature, nil) // No recipient private key provided
		require.Error(t, err)
		require.False(t, verified)
		// Construct expected public key from recipientPub for the error message
		expectedVerifierPubHex := fmt.Sprintf("%x", recipientPub.Compressed())
		require.Contains(t, err.Error(), "this signature can only be verified with knowledge of a specific private key. The associated public key is: "+expectedVerifierPubHex)
	})

	t.Run("Fails to verify a message with a wrong verifier", func(t *testing.T) {
		senderPriv, _ := ec.PrivateKeyFromBytes([]byte{15})
		_, recipientPub := ec.PrivateKeyFromBytes([]byte{21})
		wrongRecipientPriv, _ := ec.PrivateKeyFromBytes([]byte{22})

		message := []byte{1, 2, 4, 8, 16, 32}
		signature, err := Sign(message, senderPriv, recipientPub)
		require.NoError(t, err)

		verified, err := Verify(message, signature, wrongRecipientPriv)
		require.Error(t, err)
		require.False(t, verified)
		expectedRecipientPubHex := fmt.Sprintf("%x", recipientPub.Compressed())
		actualRecipientPubHex := fmt.Sprintf("%x", wrongRecipientPriv.PubKey().Compressed())
		require.Equal(t, fmt.Sprintf("the recipient public key is %s but the signature requires the recipient to have public key %s", actualRecipientPubHex, expectedRecipientPubHex), err.Error())
	})

}

func TestTamperedMessage_AnyoneCanVerify(t *testing.T) {
	senderPriv, _ := ec.PrivateKeyFromBytes([]byte{15})

	messageA := []byte{1, 2, 4, 8, 16, 32}
	signatureFromA, err := Sign(messageA, senderPriv, nil) // nil for "anyone can verify"
	require.NoError(t, err)

	// Create a tampered message (messageB)
	messageB := make([]byte, len(messageA))
	copy(messageB, messageA)
	messageB[len(messageB)-1] = 64 // Modify the last byte

	// Attempt to verify signatureFromA against messageB
	// This verification should fail if the system is working correctly.
	verified, err := Verify(messageB, signatureFromA, nil) // nil recipient
	require.NoError(t, err, "Verification process itself should not error for a tampered message if signature format is valid")
	require.False(t, verified, "Verification should fail for a tampered message")
}

func TestTamperedMessage_SpecificRecipient(t *testing.T) {
	senderPriv, _ := ec.PrivateKeyFromBytes([]byte{15})
	recipientPriv, recipientPub := ec.PrivateKeyFromBytes([]byte{21})

	messageA := []byte{1, 2, 4, 8, 16, 32}
	signatureFromA, err := Sign(messageA, senderPriv, recipientPub)
	require.NoError(t, err)

	// Create a tampered message (messageB)
	messageB := make([]byte, len(messageA))
	copy(messageB, messageA)
	messageB[len(messageB)-1] = 64 // Modify the last byte

	// Attempt to verify signatureFromA against messageB
	// This verification should fail if the system is working correctly.
	verified, err := Verify(messageB, signatureFromA, recipientPriv)
	require.NoError(t, err, "Verification process itself should not error for a tampered message if signature format is valid")
	require.False(t, verified, "Verification should fail for a tampered message with a specific recipient")
}

func TestEdgeCases(t *testing.T) {
	signingPriv, _ := ec.PrivateKeyFromBytes([]byte{15})

	message := make([]byte, 32)
	for range 10000 {
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
	}
}
