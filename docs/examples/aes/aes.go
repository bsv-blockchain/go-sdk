package main

import (
	"encoding/hex"
	"fmt"

	aes "github.com/bsv-blockchain/go-sdk/v2/primitives/aesgcm"
)

// Vanilla AES encryption and decryption
func main() {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	// Encrypt using the public key of the given private key
	encryptedData, err := aes.AESEncrypt([]byte("0123456789abcdef"), key)
	if err != nil {
		fmt.Println(err)
	}

	// Decrypt using the private key
	decryptedData, err := aes.AESDecrypt(encryptedData, key)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("decryptedData: %s\n", decryptedData)
}
