package main

import (
	"fmt"
	"log"

	ec "github.com/bsv-blockchain/go-sdk/v2/primitives/ec"
	hash "github.com/bsv-blockchain/go-sdk/v2/primitives/hash"
)

func main() {
	// Alice and Bob generate their private keys
	alicePrivKey, err := ec.NewPrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	alicePubKey := alicePrivKey.PubKey()

	bobPrivKey, err := ec.NewPrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	bobPubKey := bobPrivKey.PubKey()

	// Both parties agree on an invoice number to use
	invoiceNumber := "2-simple signing protocol-1"

	// Alice derives a child private key for signing
	aliceSigningChild, err := alicePrivKey.DeriveChild(bobPubKey, invoiceNumber)
	if err != nil {
		log.Fatal(err)
	}

	// Alice signs a message for Bob
	message := hash.Sha256([]byte("Hi Bob"))
	signature, err := aliceSigningChild.Sign(message)
	if err != nil {
		log.Fatal(err)
	}

	// Bob derives Alice's correct signing public key from her master public key
	aliceSigningPub, err := alicePubKey.DeriveChild(bobPrivKey, invoiceNumber)
	if err != nil {
		log.Fatal(err)
	}

	// Now, Bob can privately verify Alice's signature
	verified := aliceSigningPub.Verify(message, signature)
	fmt.Println("Verified:", verified)
	// Output should be true if everything is correct
}
