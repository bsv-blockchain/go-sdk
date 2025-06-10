package message

import (
	"bytes"
	"fmt"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/v2/primitives/ec"
)

func TestEncryptedMessage(t *testing.T) {
	t.Run("Encrypts a message for a recipient", func(t *testing.T) {
		sender, _ := ec.PrivateKeyFromBytes([]byte{15})
		recipient, recipientPub := ec.PrivateKeyFromBytes([]byte{21})

		msg := []byte{1, 2, 4, 8, 16, 32}

		encrypted, err := Encrypt(msg, sender, recipientPub)
		if err != nil {
			t.Fatalf("Error encrypting message: %v", err)
		}
		decrypted, err := Decrypt(encrypted, recipient)
		if err != nil {
			t.Fatalf("Error decrypting message: %v", err)
		}
		if !bytes.Equal(decrypted, msg) {
			t.Errorf("Decrypted message does not match original message")
		}
	})

	t.Run("Fails to decrypt a message with wrong version", func(t *testing.T) {
		sender, _ := ec.PrivateKeyFromBytes([]byte{15})
		recipient, recipientPub := ec.PrivateKeyFromBytes([]byte{21})

		msg := []byte{1, 2, 4, 8, 16, 32}

		encrypted, err := Encrypt(msg, sender, recipientPub)
		if err != nil {
			t.Fatalf("Error encrypting message: %v", err)
		}

		// Modify the version
		encrypted[0] = 1

		_, err = Decrypt(encrypted, recipient)
		if err == nil {
			t.Fatalf("Expected an error, but got none")
		}
		expectedError := "message version mismatch: Expected 42421033, received 01421033"
		if err.Error() != expectedError {
			t.Errorf("Expected error: %s, but got: %s", expectedError, err.Error())
		}
	})

	t.Run("Fails to decrypt a message with wrong recipient", func(t *testing.T) {
		sender, _ := ec.PrivateKeyFromBytes([]byte{15})
		_, recipientPub := ec.PrivateKeyFromBytes([]byte{21})
		wrongRecipient, _ := ec.PrivateKeyFromBytes([]byte{22})

		msg := []byte{1, 2, 4, 8, 16, 32}

		encrypted, err := Encrypt(msg, sender, recipientPub)
		if err != nil {
			t.Fatalf("Error encrypting message: %v", err)
		}

		_, err = Decrypt(encrypted, wrongRecipient)
		if err == nil {
			t.Fatalf("Expected an error, but got none")
		}
		expectedError := fmt.Sprintf("the encrypted message expects a recipient public key of %x, but the provided key is %x", recipientPub.Compressed(), wrongRecipient.PubKey().Compressed())
		if err.Error() != expectedError {
			t.Errorf("Expected error: %s, but got: %s", expectedError, err.Error())
		}
	})
}
