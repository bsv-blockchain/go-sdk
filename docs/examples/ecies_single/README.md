# ECIES Single Keypair Encryption/Decryption Example

This example demonstrates using the `ecies` compatibility package for ECIES (Elliptic Curve Integrated Encryption Scheme) to encrypt data for oneself (i.e., encrypting with a public key derived from a private key, and then decrypting with that same private key). The encrypted message is base64 encoded and prefixed with "BIE1".

## Overview

The `ecies_single` example showcases:
1. Defining a private key.
2. Encrypting a string message ("hello world") using `ecies.EncryptSingle`. This function takes the message and the user's private key. It internally derives the corresponding public key for encryption. The output is a base64 encoded string with the "BIE1" prefix.
3. Decrypting the base64 encoded ciphertext using `ecies.DecryptSingle`, which takes the encrypted string and the same private key used for encryption.

This is useful for encrypting data that only the owner of the private key should be able to decrypt, such as storing sensitive information.

## Code Walkthrough

### Encrypting and Decrypting Data for Oneself

```go
// Define a private key
myPrivateKey, _ := ec.PrivateKeyFromWif("L211enC224G1kV8pyyq7bjVd9SxZebnRYEzzM3i7ZHCc1c5E7dQu")

// Encrypt the message using the private key (public key is derived internally)
encryptedData, _ := ecies.EncryptSingle("hello world", myPrivateKey)
fmt.Println(encryptedData) // Prints BIE1-prefixed base64 string

// Decrypt the message using the same private key
decryptedData, _ := ecies.DecryptSingle(encryptedData, myPrivateKey)
fmt.Printf("Decrypted data: %s\n", decryptedData)
```

This section shows:
- `ecies.EncryptSingle` encrypts the data using the public key associated with `myPrivateKey`.
- `ecies.DecryptSingle` decrypts the data using `myPrivateKey`.

## Running the Example

To run this example:

```bash
go run ecies_single.go
```
The output will be the "BIE1" prefixed base64 encoded encrypted string, followed by the successfully decrypted "hello world" message.

**Note**:
- The WIF string for the private key is hardcoded for simplicity. In real applications, keys should be managed securely.
- The "BIE1" prefix indicates a specific ECIES message format.

## Integration Steps

To encrypt data for yourself and later decrypt it:

**For Encryption:**
1. Obtain your `*ec.PrivateKey`.
2. Call `ecies.EncryptSingle(plaintextMessageString, yourPrivateKey)`. Store the resulting BIE1-prefixed base64 string.

**For Decryption:**
1. Obtain your `*ec.PrivateKey` (the same one used for encryption).
2. Call `ecies.DecryptSingle(bie1EncryptedString, yourPrivateKey)`.

This pattern is suitable for encrypting data at rest where the same entity controls both encryption and decryption.

## Additional Resources

For more information, see:
- [Package Documentation - ECIES compatibility](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/compat/ecies)
- [Package Documentation - EC primitives](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/primitives/ec)
- [ECIES Shared Secret Example](../ecies_shared/)
- [ECIES Electrum Binary Example](../ecies_electrum_binary/)
