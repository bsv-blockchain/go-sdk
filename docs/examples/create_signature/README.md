# Create and Verify Signature Example

This example demonstrates how to use the `wallet` package to create a digital signature for a piece of data (or its hash) and then verify that signature, focusing on operations performed by a single wallet (self-signing and self-verification).

## Overview

Digital signatures provide a way to verify the authenticity and integrity of data. The process involves:
1. **Signing**: The sender uses their private key to create a signature for the data.
2. **Verification**: The recipient (or the sender themselves) uses the corresponding public key to verify the signature.

The `wallet.Wallet` provides functionality for both creating and verifying ECDSA signatures.

## Example Overview

This example demonstrates:

1. Creating a wallet instance (`signerWallet`).
2. Defining data to be signed.
3. Creating a signature for that data using `signerWallet`, configured for a "self" operation.
4. Verifying the signature using `signerWallet` itself.
5. Demonstrating verification failure with tampered data.
6. Demonstrating signing a pre-computed hash of data (for a "self" operation) and verifying it with `signerWallet`.

## Code Walkthrough

### 1. Setup Wallet

```go
privateKey, _ := ec.NewPrivateKey()
signerWallet, _ := wallet.NewWallet(privateKey)

selfProtocolID := wallet.Protocol{Protocol: "ECDSA SelfSign", SecurityLevel: wallet.SecurityLevelSilent}
selfKeyID := "my signing key v1"
```
We create a wallet and define a `ProtocolID` and `KeyID` for our self-signing operations. `KeyID` is mandatory for these wallet operations.

### 2. Define Data and Create Signature (for Self)

```go
message := []byte("This is the message to be signed by myself, for myself.")

createSigArgs := wallet.CreateSignatureArgs{
    EncryptionArgs: wallet.EncryptionArgs{
        ProtocolID: selfProtocolID,
        KeyID:      selfKeyID,
        Counterparty: wallet.Counterparty{ // Explicitly set for self-signing
            Type: wallet.CounterpartyTypeSelf,
        },
    },
    Data: wallet.JsonByteNoBase64(message),
}
sigResult, _ := signerWallet.CreateSignature(context.Background(), createSigArgs, "signer_originator")
```
To sign for "self", `EncryptionArgs.Counterparty` is explicitly set to `wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}`.

### 3. Verify Signature (by Self)

```go
verifyArgs := wallet.VerifySignatureArgs{
    EncryptionArgs: wallet.EncryptionArgs{
        ProtocolID: selfProtocolID, // Must match signing
        KeyID:      selfKeyID,      // Must match signing
        Counterparty: wallet.Counterparty{ // Explicitly set for self-verification
            Type: wallet.CounterpartyTypeSelf,
        },
    },
    Data:      wallet.JsonByteNoBase64(message),
    Signature: sigResult.Signature,
    // ForSelf field is NOT used here; Counterparty in EncryptionArgs dictates self-verification
}
verifyResult, _ := signerWallet.VerifySignature(context.Background(), verifyArgs, "verifier_originator")
// verifyResult.Valid will be true
```
To verify a signature made by the same wallet (self-verification), `EncryptionArgs.Counterparty` is again set to `wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}`. The top-level `ForSelf` field in `VerifySignatureArgs` is not used in this scenario.

### 4. Verification with Tampered Data (Failure Case)

```go
tamperedMessage := []byte("This is NOT the message that was signed.")
verifyArgsTampered := verifyArgs
verifyArgsTampered.Data = wallet.JsonByteNoBase64(tamperedMessage)

// This call is expected to return an error, or result.Valid == false
tamperedVerifyResult, err := signerWallet.VerifySignature(context.Background(), verifyArgsTampered, "verifier_tampered_originator")
// if err != nil, verification failed as expected.
// if err == nil and !tamperedVerifyResult.Valid, verification failed as expected.
```
If the data is altered, `VerifySignature` will indicate failure, either by returning an error (e.g., "signature is not valid") or by returning a result with `Valid` as `false`.

### 5. Signing and Verifying a Pre-computed Hash (for Self)

Similar to signing raw data, when signing a pre-computed hash for a "self" operation:

```go
messageHash := sha256.Sum256(message) // Pre-compute SHA256 hash

createSigForHashArgs := wallet.CreateSignatureArgs{
    EncryptionArgs: wallet.EncryptionArgs{
        ProtocolID: /* define appropriate ProtocolID */,
        KeyID:      /* define appropriate KeyID */,
        Counterparty: wallet.Counterparty{
            Type: wallet.CounterpartyTypeSelf,
        },
    },
    HashToDirectlySign: wallet.JsonByteNoBase64(messageHash[:]),
}
sigFromHashResult, _ := signerWallet.CreateSignature(context.Background(), createSigForHashArgs, "signer_originator_hash")

// Verification of signature made from hash (by self)
verifyHashArgs := wallet.VerifySignatureArgs{
    EncryptionArgs: createSigForHashArgs.EncryptionArgs, // Match args from hash signing
    HashToDirectlyVerify: wallet.JsonByteNoBase64(messageHash[:]),
    Signature:            sigFromHashResult.Signature,
}
verifyHashResult, _ := signerWallet.VerifySignature(context.Background(), verifyHashArgs, "verifier_originator_hash")
// verifyHashResult.Valid will be true
```
Again, `CounterpartyTypeSelf` is used in `EncryptionArgs` for both creation and verification.

## Running the Example

To run this example:

```bash
cd go-sdk/docs/examples/create_signature
go mod tidy
go run create_signature.go
```

## Key Concepts

- **Digital Signature**: Ensures data authenticity and integrity.
- **ECDSA**: Elliptic Curve Digital Signature Algorithm.
- **`wallet.CreateSignatureArgs` / `wallet.VerifySignatureArgs`**: Structs for signing/verification parameters.
- **`EncryptionArgs`**: Embedded in the above, contains `ProtocolID`, `KeyID`, and `Counterparty`.
- **`KeyID`**: Mandatory identifier for keying material. Length must be >= 1 character.
- **`ProtocolID.Protocol`**: String identifying the protocol. Length must be >= 5 chars, containing only letters, numbers, and spaces.
- **`CounterpartyTypeSelf`**: Used in `EncryptionArgs.Counterparty.Type` when a wallet signs data for itself or verifies its own signatures.
- When using `wallet.VerifySignature` for self-verification with `CounterpartyTypeSelf` in `EncryptionArgs`, the top-level `VerifySignatureArgs.ForSelf` field is not set.

## Additional Resources

- [go-sdk `wallet` package documentation](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/wallet)
- [go-sdk `primitives/ec` package documentation](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/primitives/ec)
- SDK tests, particularly `wallet/wallet_test.go` (`TestDefaultSignatureOperations`), can provide further examples.
