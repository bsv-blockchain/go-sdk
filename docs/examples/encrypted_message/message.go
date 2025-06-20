package main

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/message"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func main() {
	sender, _ := ec.NewPrivateKey()
	recipient, _ := ec.NewPrivateKey()

	msg := []byte{1, 2, 4, 8, 16, 32}

	// Encrypt a message using the sender's private key and the recipient's public key
	encryptedData, _ := message.Encrypt(msg, sender, recipient.PubKey())

	// Decrypt a message using the private key of the recipient
	decryptedData, _ := message.Decrypt(encryptedData, recipient)

	fmt.Printf("decryptedData: %s\n", decryptedData)

	// sign message for a recipient
	signature, _ := message.Sign(msg, sender, recipient.PubKey())
	verified, _ := message.Verify(msg, signature, recipient)
	fmt.Printf("verified: %t\n", verified)

	// sign a message for anyone
	signature, _ = message.Sign(msg, sender, nil)
	verified, _ = message.Verify(msg, signature, nil)
	fmt.Printf("verified: %t\n", verified)
}
