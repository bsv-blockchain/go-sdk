package main

import (
	"log"

	bip32 "github.com/bsv-blockchain/go-sdk/compat/bip32"
)

func main() {
	xPrivateKey, xPublicKey, err := bip32.GenerateHDKeyPair(bip32.SecureSeedLength)
	if err != nil {
		log.Fatalf("error occurred: %s", err.Error())
	}

	// Success!
	log.Printf("xPrivateKey: %s \n xPublicKey: %s", xPrivateKey, xPublicKey)
}
