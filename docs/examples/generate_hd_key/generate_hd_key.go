package main

import (
	"crypto/sha256"
	"log"

	bip32 "github.com/bsv-blockchain/go-sdk/compat/bip32"
)

func main() {
	xPrivateKey, xPublicKey, err := bip32.GenerateHDKeyPair(bip32.SecureSeedLength)
	if err != nil {
		log.Fatalf("error occurred: %s", err.Error())
	}

	// Success! Avoid logging sensitive key material. Use a fingerprint of the public key
	// for verification instead of printing the full keys.
	publicKeyFingerprint := sha256.Sum256([]byte(xPublicKey))
	log.Printf("Generated HD key pair (xPriv length: %d, xPub fingerprint: %x)", len(xPrivateKey), publicKeyFingerprint[:8])
}
