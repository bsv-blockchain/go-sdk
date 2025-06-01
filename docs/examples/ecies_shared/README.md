# ECIES Shared Key Encryption/Decryption Example

This example demonstrates using the `ecies` compatibility package for ECIES (Elliptic Curve Integrated Encryption Scheme) encryption and decryption of a message where a shared secret is derived from one party's private key and another party's public key. The encrypted message is base64 encoded and prefixed with "BIE1" (Bitcoin Information Encryption, version 1), a common convention for ECIES encrypted messages.

## Overview

The `ecies_shared` example showcases:
1. Defining "my" private key (sender/encryptor).
2. Defining the recipient's public key.
3. Encrypting a string message ("hello world") using `ecies.EncryptShared`. This function takes the message, the recipient's public key, and the sender's private key. It returns a base64 encoded string with the "BIE1" prefix.
4. Decrypting the base64 encoded ciphertext using `ecies.DecryptShared`. This requires the recipient's private key (here simulated by `myPrivateKey` as if "I" am the recipient) and the sender's public key (here `recipientPublicKey`, which is a slight misnomer if `myPrivateKey` is the decrypter; it should be the public key of the original encryptor).

**Clarification on Decryption Keys:**
- To **encrypt** for a recipient: You use *your* private key and the *recipient's* public key.
- To **decrypt** a message sent to you: You use *your* private key and the *sender's* public key.

The example uses `myPrivateKey` for both encryption (as sender) and decryption (as if `myPrivateKey` corresponds to the recipient for whom the message was encrypted). If a different party (Recipient) were to decrypt, they would use *their own* private key and the public key derived from `myPrivateKey` (the original sender's public key).

## Code Walkthrough

### Encrypting and Decrypting Data

```go
// My private key (used for encryption, and also for decryption in this example)
myPrivateKey, _ := ec.PrivateKeyFromWif("L211enC224G1kV8pyyq7bjVd9SxZebnRYEzzM3i7ZHCc1c5E7dQu")

// Recipient's public key (target for encryption)
recipientPublicKey, _ := ec.PublicKeyFromString("03121a7afe56fc8e25bca4bb2c94f35eb67ebe5b84df2e149d65b9423ee65b8b4b")

// Encrypt the message for the recipient
// Uses myPrivateKey (sender) and recipientPublicKey
encryptedData, _ := ecies.EncryptShared("hello world", recipientPublicKey, myPrivateKey)
fmt.Println(encryptedData) // Prints BIE1-prefixed base64 string

// Decrypt the message
// To be decrypted by the actual recipient, they would use their private key
// (corresponding to recipientPublicKey) and myPrivateKey.PubKey() (sender's public key).
// This example shows decryption using myPrivateKey and recipientPublicKey,
// which implies either decrypting one's own message or a specific scenario.
decryptedData, _ := ecies.DecryptShared(encryptedData, myPrivateKey, recipientPublicKey)
fmt.Printf("Decrypted data: %s\n", decryptedData)
```

This section shows:
- `ecies.EncryptShared` taking the plaintext, the public key of the intended recipient, and the private key of the sender. It produces a "BIE1" prefixed base64 string.
- `ecies.DecryptShared` taking this base64 string, the private key of the party performing the decryption, and the public key of the other party involved in the key exchange (the original encryptor).

## Running the Example

To run this example:

```bash
go run ecies_shared.go
```
The output will be the "BIE1" prefixed base64 encoded encrypted string, followed by the successfully decrypted "hello world" message.

**Note**:
- WIF and public key strings are hardcoded for simplicity.
- The "BIE1" prefix is a convention indicating a specific ECIES message format, often used in Bitcoin-related applications.
- For correct decryption by an independent recipient:
    - The recipient must use *their own* private key (the one corresponding to `recipientPublicKey`).
    - The recipient must use the *sender's* public key (which is `myPrivateKey.PubKey()` in this example's context).

## Integration Steps

**For Encryption (Sender):**
1. Obtain the sender's `*ec.PrivateKey`.
2. Obtain the recipient's `*ec.PublicKey`.
3. Call `ecies.EncryptShared(plaintextMessageString, recipientPubKey, senderPrivKey)`.

**For Decryption (Recipient):**
1. Obtain the recipient's `*ec.PrivateKey`.
2. Obtain the sender's `*ec.PublicKey`.
3. Call `ecies.DecryptShared(bie1EncryptedString, recipientPrivKey, senderPubKey)`.

## Additional Resources

For more information, see:
- [Package Documentation - ECIES compatibility](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/compat/ecies)
- [Package Documentation - EC primitives](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/primitives/ec)
- [ECIES Electrum Binary Example](../ecies_electrum_binary/)
- [ECIES Single Keypair Example](../ecies_single/)
