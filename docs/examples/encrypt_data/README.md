# Encrypt and Decrypt Data Example

This example demonstrates how to use the `wallet` package to encrypt and decrypt data between two parties (or for oneself) using ECIES (Elliptic Curve Integrated Encryption Scheme).

## Overview

The `wallet.Wallet` provides functionality to:
1. Encrypt data for a recipient (identified by their public key or a derived path).
2. Decrypt data that was encrypted for the wallet holder.

This example will simulate a scenario where Alice wants to send an encrypted message to Bob. We will:
- Create a wallet for Alice and a wallet for Bob.
- Alice will encrypt a message using Bob's public key.
- Bob will decrypt the message using his private key.

We will also demonstrate encrypting data for oneself (e.g., for secure local storage).

## Example Overview

This example demonstrates:

1. Creating two distinct wallets (Alice and Bob).
2. Alice obtaining Bob's public key (for encryption).
3. Alice encrypting a message for Bob.
4. Bob decrypting the message received from Alice.
5. Alice encrypting a message for herself.
6. Alice decrypting her own message.

## Code Walkthrough

### 1. Setup Wallets

```go
// Create Alice's wallet (replace with actual key generation/retrieval)
alicePrivKey, _ := ec.NewPrivateKey()
aliceWallet, _ := wallet.NewWallet(alicePrivKey)

// Create Bob's wallet
bobPrivKey, _ := ec.NewPrivateKey()
bobWallet, _ := wallet.NewWallet(bobPrivKey)
```
We start by creating two wallet instances using newly generated `ec.PrivateKey` values. In a real application, these private keys would be securely generated and stored, or derived using mnemonics as shown in the `create_wallet` example.

### 2. Alice Gets Bob's Public Key

```go
// Alice needs Bob's public key to encrypt data for him.
bobIdentityKeyArgs := wallet.GetPublicKeyArgs{IdentityKey: true}
bobPubKeyResult, _ := bobWallet.GetPublicKey(context.Background(), bobIdentityKeyArgs, "bob_originator_get_pubkey")
bobECPubKey := bobPubKeyResult.PublicKey
```
Alice needs Bob's public key to encrypt data for him. The `IdentityKey: true` argument ensures we get a stable public key suitable for ECIES. The `bobPubKeyResult.PublicKey` is directly an `*ec.PublicKey`.

### 3. Alice Encrypts Data for Bob

```go
plaintext := []byte("Hello Bob, this is a secret message from Alice!")
encryptArgs := wallet.EncryptArgs{
    EncryptionArgs: wallet.EncryptionArgs{
        Counterparty: wallet.Counterparty{
            Type:         wallet.CounterpartyTypeOther,
            Counterparty: bobECPubKey, // Note: field name is Counterparty
        },
        ProtocolID: wallet.Protocol{
            Protocol:      "ECIES",
            SecurityLevel: wallet.SecurityLevelSilent,
        },
        KeyID: "AliceToBobECIES_Key1", // KeyID for this specific encryption context
    },
    Plaintext: wallet.JsonByteNoBase64(plaintextForBob),
}
encryptedResult, err := aliceWallet.Encrypt(context.Background(), encryptArgs, "alice_encrypt_for_bob")
```
Alice uses her wallet to encrypt the plaintext. She specifies Bob's public key via `CounterpartyTypeOther` and assigning `bobECPubKey` to the `Counterparty` field. The protocol is "ECIES" with `SecurityLevelSilent`. A `KeyID` is provided to uniquely identify this encryption context, which is important for key derivation within ECIES.

### 4. Bob Decrypts Data from Alice

```go
// Bob needs Alice's public key for decryption context
aliceIdentityKeyArgs := wallet.GetPublicKeyArgs{IdentityKey: true}
alicePubKeyResult, _ := aliceWallet.GetPublicKey(context.Background(), aliceIdentityKeyArgs, "alice_originator_get_pubkey")
aliceECPubKey := alicePubKeyResult.PublicKey

decryptArgs := wallet.DecryptArgs{
    EncryptionArgs: wallet.EncryptionArgs{
        Counterparty: wallet.Counterparty{
            Type:         wallet.CounterpartyTypeOther,
            Counterparty: aliceECPubKey, // Bob specifies Alice's public key
        },
        ProtocolID: wallet.Protocol{
            Protocol:      "ECIES",
            SecurityLevel: wallet.SecurityLevelSilent,
        },
        KeyID: "AliceToBobECIES_Key1", // Must match the KeyID Alice used
    },
    Ciphertext: encryptedResult.Ciphertext,
}
decryptedResult, err := bobWallet.Decrypt(context.Background(), decryptArgs, "bob_decrypt_from_alice")
```
Bob uses his wallet to decrypt the ciphertext. He specifies Alice's public key as the counterparty and **must use the same `KeyID`** that Alice used during encryption for the correct decryption key to be derived.

### 5. Encrypting and Decrypting for Self

```go
// Alice encrypts for herself
selfEncryptArgs := wallet.EncryptArgs{
    EncryptionArgs: wallet.EncryptionArgs{
        Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
        ProtocolID: wallet.Protocol{
            Protocol:      "ECIES",
            SecurityLevel: wallet.SecurityLevelSilent,
        },
        KeyID: "AliceSelfECIES_Key1", // A different KeyID for self-encryption context
    },
    Plaintext: wallet.JsonByteNoBase64([]byte("My own secret note.")),
}
selfEncrypted, _ := aliceWallet.Encrypt(context.Background(), selfEncryptArgs, "alice_encrypt_for_self")

// Alice decrypts her own message
selfDecryptArgs := wallet.DecryptArgs{
    EncryptionArgs: wallet.EncryptionArgs{
        Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
        ProtocolID: wallet.Protocol{
            Protocol:      "ECIES",
            SecurityLevel: wallet.SecurityLevelSilent,
        },
        KeyID: "AliceSelfECIES_Key1", // Must match self-encryption KeyID
    },
    Ciphertext: selfEncrypted.Ciphertext,
}
selfDecrypted, _ := aliceWallet.Decrypt(context.Background(), selfDecryptArgs, "alice_decrypt_for_self")
```
Encrypting for oneself uses `CounterpartyTypeSelf`. A `KeyID` is also used here and must be consistent between encryption and decryption.

## Running the Example

To run this example:

```bash
cd go-sdk/docs/examples/encrypt_data
go mod tidy # (if you haven't run it before or added new imports)
go run encrypt_data.go
```

## Key Concepts

- **ECIES**: Elliptic Curve Integrated Encryption Scheme. A hybrid encryption scheme.
- **Wallet**: Manages cryptographic keys and provides encryption/decryption.
- **Identity Key**: A stable public key from a wallet for identification/encryption.
- **CounterpartyTypeOther**: Used when specifying an explicit `*ec.PublicKey` for the other party.
- **CounterpartyTypeSelf**: Used for encrypting/decrypting data for the wallet holder itself.
- **ProtocolID**: Specifies the cryptographic protocol (e.g., "ECIES") and its security level.
- **KeyID**: An identifier used in key derivation, crucial for ensuring the correct keys are derived for encryption and decryption. Must be consistent for an encryption/decryption pair.

## Additional Resources

- [go-sdk `wallet` package](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/wallet)
- [go-sdk `primitives/ec` package](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/primitives/ec)
