package main

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/v2/primitives/ec"
)

// example using BRC-42 method for deriving a child key
func main() {
	merchantPrivKey, _ := ec.PrivateKeyFromWif("L4PoBVNHZb9wVs9TFqyFrKxmpkJPPyzbjQrCiiQUoCz7ceAq63Rt")

	invoiceNum := "test invoice number"

	customerPubKeyStr := "03121a7afe56fc8e25bca4bb2c94f35eb67ebe5b84df2e149d65b9423ee65b8b4b"
	customerPubKey, _ := ec.PublicKeyFromString(customerPubKeyStr)

	child, _ := merchantPrivKey.DeriveChild(customerPubKey, invoiceNum)

	fmt.Printf("%x", child.Serialize())
	// now use the child key to sign a message, transaction, etc
}
