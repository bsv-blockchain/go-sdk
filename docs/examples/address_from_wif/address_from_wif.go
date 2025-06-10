package main

import (
	"log"

	ec "github.com/bsv-blockchain/go-sdk/v2/primitives/ec"
	script "github.com/bsv-blockchain/go-sdk/v2/script"
)

func main() {

	priv, _ := ec.PrivateKeyFromWif("Kxfd8ABTYZHBH3y1jToJ2AUJTMVbsNaqQsrkpo9gnnc1JXfBH8mn")

	// Print the private key
	log.Printf("Private key: %x\n", priv.Serialize())
	address, _ := script.NewAddressFromPublicKey(priv.PubKey(), true)

	// Print the address, and the pubkey hash
	println(address.AddressString, address.PublicKeyHash)

}
