package main

import (
	"fmt"

	ecies "github.com/bsv-blockchain/go-sdk/v2/compat/ecies"
	ec "github.com/bsv-blockchain/go-sdk/v2/primitives/ec"
)

// Example of using ECIES to encrypt and decrypt data between two users

func main() {

	myPrivateKey, _ := ec.PrivateKeyFromWif("L211enC224G1kV8pyyq7bjVd9SxZebnRYEzzM3i7ZHCc1c5E7dQu")
	recipientPublicKey, _ := ec.PublicKeyFromString("03121a7afe56fc8e25bca4bb2c94f35eb67ebe5b84df2e149d65b9423ee65b8b4b")

	encryptedData, _ := ecies.EncryptShared("hello world", recipientPublicKey, myPrivateKey)

	fmt.Println(encryptedData)
	// Prints:
	// QklFMQO7zpX/GS4XpthCy6/hT38ZKsBGbn8JKMGHOY5ifmaoT+nbjXrzxPofyG94/QHgX8QZ3+a/DfQbTJ+Qvm1KtZWZISHww7MM5oRZybxHjtAa+Q==

	decryptedData, _ := ecies.DecryptShared(encryptedData, myPrivateKey, recipientPublicKey)
	fmt.Printf("decryptedData: %s\n", decryptedData)
	// Prints:
	// decryptedData: hello world
}

// // user 1
// user1Pk, _ := ec.NewPrivateKey()

// // user 2
// user2Pk, _ := ec.PublicKeyFromString("03121a7afe56fc8e25bca4bb2c94f35eb67ebe5b84df2e149d65b9423ee65b8b4b")

// priv, _, encryptedData, _ := ec.EncryptShared(user1Pk, user2Pk, []byte("this is a test"))

// decryptedData, _ := ec.DecryptWithPrivateKey(priv, hex.EncodeToString(encryptedData))

// fmt.Printf("decryptedData: %s\n", decryptedData)
// }
