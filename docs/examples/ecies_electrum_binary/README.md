# ECIES Electrum Binary Encryption/Decryption Example

This example demonstrates how to use the `ecies` compatibility package (specifically `ecies.ElectrumEncrypt` and `ecies.ElectrumDecrypt`) for encrypting and decrypting data between two parties using their ECIES (Elliptic Curve Integrated Encryption Scheme) compatible keys, with a focus on Electrum-style binary message formatting.

## Overview

The `ecies_electrum_binary` example showcases:
1. Defining a private key for User 1 (the sender, who will also be able to decrypt if they use their own public key, or if encrypting for themselves).
2. Defining a public key for User 2 (the recipient).
3. Encrypting a message ("hello world") using User 1's private key (for deriving the shared secret) and User 2's public key (as the recipient's key). The `false` flag indicates binary (non-magic-message) ECIES.
4. Decrypting the encrypted data using User 1's private key (if User 1 was the recipient) or User 2's private key (if User 2 is decrypting, which requires User 2's private key not shown in this sender-focused example) and the sender's public key (User 1's public key, derived from `user1Pk`).

**Important Clarification for ECIES Decryption:**
Standard ECIES involves:
- **Encryption**: Sender uses their own private key and the recipient's public key.
- **Decryption**: Recipient uses their own private key and the sender's public key.

This example simplifies by having User 1 encrypt for User 2. For User 2 to decrypt, they would need `user2Pk`'s corresponding private key and User 1's public key. The example decrypts from User 1's perspective (User 1 decrypting a message intended for User 2, which works if User 1's private key and User 2's public key were used in encryption, and then User 1's private key and User 2's public key are used for decryption - effectively User 1 decrypting their own message to User 2).

## Code Walkthrough

### Encrypting and Decrypting Data

```go
// User 1's private key (sender)
user1PrivKey, _ := ec.PrivateKeyFromWif("L211enC224G1kV8pyyq7bjVd9SxZebnRYEzzM3i7ZHCc1c5E7dQu")

// User 2's public key (recipient)
user2PubKey, _ := ec.PublicKeyFromString("03121a7afe56fc8e25bca4bb2c94f35eb67ebe5b84df2e149d65b9423ee65b8b4b")

// Encrypt data from User 1 to User 2 (binary format)
// The sender's private key (user1PrivKey) is used with the recipient's public key (user2PubKey)
encryptedData, _ := ecies.ElectrumEncrypt([]byte("hello world"), user2PubKey, user1PrivKey, false)

fmt.Println("Encrypted data (may not be human-readable):", string(encryptedData)) // Note: binary data might not print well as a string

// Decrypt data:
// To be decrypted by User 2 (recipient), they would use their private key (corresponding to user2PubKey)
// and User 1's public key (derived from user1PrivKey).
// The example shows User 1 decrypting, which also works using their own private key and User 2's public key.
decryptedData, _ := ecies.ElectrumDecrypt(encryptedData, user1PrivKey, user2PubKey)

fmt.Printf("Decrypted data: %s\n", decryptedData)
```

This section shows User 1 encrypting a message for User 2. `ElectrumEncrypt` uses User 2's public key as the encryption target and User 1's private key to help form the shared secret. The `false` argument specifies the binary ECIES variant (as opposed to one with a "BIE1" magic message prefix).
The decryption step shown uses User 1's private key and User 2's public key. This means User 1 is decrypting the message. For User 2 to decrypt it, they would need their own private key (the one corresponding to `user2PubKey`) and User 1's public key (derived from `user1PrivKey`).

## Running the Example

To run this example:

```bash
go run ecies_electrum_binary.go
```
The output will show the (potentially non-human-readable) encrypted data and then the successfully decrypted "hello world" message.

**Note**:
- The WIF and public key strings are hardcoded. In real applications, these would be managed securely and obtained dynamically.
- The `ElectrumEncrypt` and `ElectrumDecrypt` functions are specific implementations of ECIES, potentially with formatting compatible with Electrum wallet's ECIES messages (when `isMagicMessage` is true). The `false` flag means it's a more generic binary ECIES.
- The key management is crucial: the sender needs their private key and the recipient's public key. The recipient needs their private key and the sender's public key.

## Integration Steps

To integrate ECIES encryption/decryption:

**For Encryption (Sender Side):**
1. Obtain the sender's `*ec.PrivateKey`.
2. Obtain the recipient's `*ec.PublicKey`.
3. Call `ecies.ElectrumEncrypt(messageBytes, recipientPubKey, senderPrivKey, false)` for binary format.

**For Decryption (Recipient Side):**
1. Obtain the recipient's `*ec.PrivateKey`.
2. Obtain the sender's `*ec.PublicKey`.
3. Call `ecies.ElectrumDecrypt(encryptedBytes, recipientPrivKey, senderPubKey)`.

Ensure that keys are exchanged securely.

## Additional Resources

For more information, see:
- [Package Documentation - ECIES compatibility](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/compat/ecies)
- [Package Documentation - EC primitives](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/primitives/ec)
- [ECIES Shared Secret Example](../ecies_shared/)
- [ECIES Single Keypair Example](../ecies_single/)
