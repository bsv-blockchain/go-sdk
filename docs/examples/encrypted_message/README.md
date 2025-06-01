# Encrypted Message and Signature Example

This example demonstrates how to use the `message` package for encrypting/decrypting messages and signing/verifying messages, leveraging ECIES and ECDSA.

## Overview

The `encrypted_message` example (using `message.go`) showcases several functionalities:
1. **Encryption**: Encrypting a message using a sender's private key and a recipient's public key via `message.Encrypt`.
2. **Decryption**: Decrypting the ciphertext using the recipient's private key via `message.Decrypt`.
3. **Targeted Signature**: Signing a message specifically for a recipient (binding the signature to the recipient's public key) using `message.Sign`.
4. **Targeted Verification**: Verifying this targeted signature using the recipient's private key (to derive the public key for verification in the context of ECIES-like key agreement for signature verification) via `message.Verify`.
5. **General Signature**: Signing a message for general verification (not tied to a specific recipient's public key for the signature scheme itself) using `message.Sign` with a `nil` recipient public key.
6. **General Verification**: Verifying this general signature using `message.Verify` with a `nil` recipient (implying verification against the sender's public key directly).

## Code Walkthrough

### Encryption and Decryption

```go
senderPrivKey, _ := ec.NewPrivateKey()
recipientPrivKey, _ := ec.NewPrivateKey()
messageBytes := []byte{1, 2, 4, 8, 16, 32}

// Encrypt using sender's private key and recipient's public key
encryptedData, _ := message.Encrypt(messageBytes, senderPrivKey, recipientPrivKey.PubKey())

// Decrypt using recipient's private key
// (The sender's public key is implicitly derived/used in the ECIES scheme)
decryptedData, _ := message.Decrypt(encryptedData, recipientPrivKey)
fmt.Printf("Decrypted Data: %s\n", decryptedData) // Note: %s might not be ideal for raw bytes
```
This part demonstrates a typical ECIES flow. `message.Encrypt` uses the sender's private key and recipient's public key. `message.Decrypt` uses the recipient's private key (the sender's public key is part of the ECIES shared secret derivation).

### Targeted Message Signing and Verification

```go
// Sign message specifically for the recipient
// This likely incorporates recipient's public key into the signing/verification process,
// possibly through a shared secret, making the signature verifiable only by the intended recipient
// or someone who can also derive that shared secret.
signatureForRecipient, _ := message.Sign(messageBytes, senderPrivKey, recipientPrivKey.PubKey())

// Verify the targeted signature using recipient's private key
// (which implies using recipient's public key in conjunction with sender's public key)
verifiedTargeted, _ := message.Verify(messageBytes, signatureForRecipient, recipientPrivKey)
fmt.Printf("Targeted signature verified: %t\n", verifiedTargeted)
```
Here, `message.Sign` with a non-nil recipient public key creates a signature that is verifiable in the context of that recipient. `message.Verify` uses the recipient's private key, suggesting it re-derives necessary public keys or shared secrets for this specific verification scheme.

### General Message Signing and Verification

```go
// Sign message for general verification (anyone with sender's public key can verify)
generalSignature, _ := message.Sign(messageBytes, senderPrivKey, nil) // Recipient public key is nil

// Verify the general signature
// With recipient key as nil, this likely defaults to standard ECDSA verification
// using the public key derived from senderPrivKey.
verifiedGeneral, _ := message.Verify(messageBytes, generalSignature, nil) // Assuming sender's public key is used
fmt.Printf("General signature verified: %t\n", verifiedGeneral)
```
This demonstrates a more standard ECDSA signature where the signature is created by the sender and can be verified by anyone who has the sender's public key. `message.Verify` with `nil` for the recipient key implies this mode.

## Running the Example

To run this example:

```bash
go run message.go
```
The output will show the decrypted data and the verification status (true) for both targeted and general signatures.

**Note**:
- The `message.Sign` and `message.Verify` functions with a non-nil recipient public key implement a specific scheme. Standard ECDSA signatures don't usually involve the recipient's key directly in the signature itself but rather for encrypting a message that might contain a signature. The `message` package appears to offer a combined or ECIES-like approach to signed/encrypted messaging.
- For "targeted" verification, the verifier (recipient) needs their private key. For "general" verification, any party can verify using the sender's public key.

## Integration Steps

**For Encrypted Messaging:**
1. **Encrypt**: `message.Encrypt(payload, senderPrivKey, recipientPubKey)`
2. **Decrypt**: `message.Decrypt(encryptedPayload, recipientPrivKey)`

**For Targeted Signed Messaging (Recipient-Specific Verification):**
1. **Sign**: `message.Sign(payload, senderPrivKey, recipientPubKey)`
2. **Verify**: `message.Verify(payload, signature, recipientPrivKey)` (Recipient verifies)

**For General Signed Messaging (Public Verification):**
1. **Sign**: `message.Sign(payload, senderPrivKey, nil)`
2. **Verify**: `message.Verify(payload, signature, nil)` (Anyone with sender's public key verifies; the `nil` here might mean the function internally uses `senderPrivKey.PubKey()` if the signature embeds it, or one would typically pass `senderPrivKey.PubKey()` if the API allowed for a public key verifier). The current API for `message.Verify` seems to expect a private key for the `verifier` argument, which it then uses to derive the necessary public key(s).

## Additional Resources

For more information, see:
- [Package Documentation - Message](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/message)
- [Package Documentation - EC primitives](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/primitives/ec)
- ECIES and ECDSA specifications.
- [Authenticated Messaging Example](../authenticated_messaging/) (for a higher-level peer-to-peer communication)
