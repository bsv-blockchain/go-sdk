# AES Encryption/Decryption Example

This example demonstrates basic AES (Advanced Encryption Standard) GCM (Galois/Counter Mode) encryption and decryption using the `aesgcm` package.

## Overview

The `aes` example showcases:
1. Defining a hexadecimal AES key.
2. Encrypting a plaintext byte slice (`[]byte("0123456789abcdef")`) using `aesgcm.AESEncrypt`.
3. Decrypting the resulting ciphertext using `aesgcm.AESDecrypt` with the same key.
4. Printing the decrypted data.

## Code Walkthrough

### Encrypting and Decrypting Data

```go
package main

import (
	"encoding/hex"
	"fmt"

	aes "github.com/bsv-blockchain/go-sdk/primitives/aesgcm"
)

func main() {
	// Define an AES key (must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256 respectively)
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f") // 16 bytes for AES-128

	plaintext := []byte("0123456789abcdef")

	// Encrypt the data
	encryptedData, err := aes.AESEncrypt(plaintext, key)
	if err != nil {
		fmt.Println("Encryption error:", err)
		return
	}
	fmt.Printf("Encrypted data (hex): %x\n", encryptedData)

	// Decrypt the data
	decryptedData, err := aes.AESDecrypt(encryptedData, key)
	if err != nil {
		fmt.Println("Decryption error:", err)
		return
	}
	fmt.Printf("Decrypted data: %s\n", decryptedData)
}
```

This section shows:
- Initialization of a 16-byte AES key.
- Encryption of a sample plaintext using `aes.AESEncrypt`. This function handles nonce generation and prepends it to the ciphertext.
- Decryption of the ciphertext using `aes.AESDecrypt`. This function extracts the nonce from the ciphertext and performs decryption.

## Running the Example

To run this example:

```bash
go run aes.go
```
The output will show the hexadecimal representation of the encrypted data, followed by the successfully decrypted original message.

**Note**:
- The key used is hardcoded. In real applications, keys should be securely generated and managed.
- The `aesgcm` package uses AES in GCM mode, which provides both confidentiality and authenticity.
- The nonce is generated internally by `AESEncrypt` and prepended to the ciphertext. `AESDecrypt` expects this format.

## Integration Steps

To use AES GCM encryption/decryption in your application:

**For Encryption:**
1. Obtain or generate a secure AES key of appropriate length (16, 24, or 32 bytes).
2. Call `ciphertext, err := aesgcm.AESEncrypt(plaintextBytes, key)`.
3. Store or transmit the `ciphertext`.

**For Decryption:**
1. Obtain the same AES key used for encryption.
2. Call `plaintextBytes, err := aesgcm.AESDecrypt(ciphertext, key)`.
3. The `plaintextBytes` will contain the original data if decryption is successful.

Ensure proper key management practices are followed.

## Additional Resources

For more information, see:
- [Package Documentation - aesgcm](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/primitives/aesgcm)
- NIST Special Publication 800-38D for GCM mode.
