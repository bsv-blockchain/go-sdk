# Create and Verify HMAC Example

This example demonstrates how to use the `wallet` package to create an HMAC (Hash-based Message Authentication Code) for a piece of data and then verify it. This is typically done by a single party to ensure data integrity and authenticity based on a shared secret derived contextually.

## Overview

HMACs provide a way to verify both the data integrity and the authenticity of a message using a shared secret (derived from the wallet's key, `ProtocolID`, `KeyID`, and `Counterparty` context). The process involves:

1.  **Creation**: A key is derived based on the wallet's private key and the provided `EncryptionArgs` (including `ProtocolID`, `KeyID`, and `Counterparty`). This key is then used with a hash function (like SHA256, commonly used with HMAC) to produce an authentication code for the data.
2.  **Verification**: The same process is followed. If the newly computed HMAC matches the original HMAC, the data is considered authentic and its integrity is verified.

The `wallet.Wallet` provides `CreateHmac` and `VerifyHmac` methods.

## Example Overview

This example demonstrates:

1.  Creating a wallet instance (`myWallet`).
2.  Defining data for which to create an HMAC.
3.  Creating an HMAC for that data using `myWallet`, configured for a "self" operation (i.e., the HMAC is for the wallet's own use or context).
4.  Verifying the HMAC using `myWallet` itself.
5.  Demonstrating verification failure with tampered data.
6.  Demonstrating verification failure with a tampered HMAC.

## Code Walkthrough

### 1. Setup Wallet

```go
privateKey, _ := ec.NewPrivateKey()
myWallet, _ := wallet.NewWallet(privateKey)

// Define ProtocolID and KeyID for HMAC operations
hmacProtocolID := wallet.Protocol{Protocol: "HMAC SelfSign", SecurityLevel: wallet.SecurityLevelSilent}
hmacKeyID := "my hmac key v1"
```
We create a wallet and define a `ProtocolID` and `KeyID`. These, along with the `Counterparty` setting, will determine the derived key used for the HMAC operation.

### 2. Define Data and Create HMAC (for Self)

```go
message := []byte("This is the data to be authenticated with HMAC.")

createHmacArgs := wallet.CreateHmacArgs{
    EncryptionArgs: wallet.EncryptionArgs{
        ProtocolID: hmacProtocolID,
        KeyID:      hmacKeyID,
        Counterparty: wallet.Counterparty{ // Explicitly set for self-operation
            Type: wallet.CounterpartyTypeSelf,
        },
    },
    Data: wallet.JsonByteNoBase64(message),
}
createHmacResult, _ := myWallet.CreateHmac(context.Background(), createHmacArgs, "creator_originator")
hmacBytes := createHmacResult.Hmac
```
To create an HMAC for a "self" context, `EncryptionArgs.Counterparty` is explicitly set to `wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}`.

### 3. Verify HMAC (by Self)

```go
verifyHmacArgs := wallet.VerifyHmacArgs{
    EncryptionArgs: wallet.EncryptionArgs{
        ProtocolID: hmacProtocolID, // Must match creation
        KeyID:      hmacKeyID,      // Must match creation
        Counterparty: wallet.Counterparty{ // Explicitly set for self-operation
            Type: wallet.CounterpartyTypeSelf,
        },
    },
    Data: wallet.JsonByteNoBase64(message), // Original data
    Hmac: hmacBytes,                        // HMAC created in the previous step
}
verifyHmacResult, _ := myWallet.VerifyHmac(context.Background(), verifyHmacArgs, "verifier_originator")
// verifyHmacResult.Valid will be true
```
To verify an HMAC made by the same wallet for a "self" context, `EncryptionArgs.Counterparty` is again set to `wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}`. The `ProtocolID` and `KeyID` must also match those used during creation.

### 4. Verification Failure Scenarios

-   **Tampered Data**: If the `Data` is changed, `VerifyHmac` will result in `Valid: false`.
    ```go
    tamperedDataArgs := verifyHmacArgs
    tamperedDataArgs.Data = wallet.JsonByteNoBase64([]byte("Tampered data!"))
    // Result will have Valid: false
    ```
-   **Tampered HMAC**: If the `Hmac` itself is changed, `VerifyHmac` will result in `Valid: false`.
    ```go
    tamperedHmacArgs := verifyHmacArgs
    tamperedHmac := append([]byte{0x00}, hmacBytes...) // Alter the HMAC slightly
    tamperedHmacArgs.Hmac = wallet.JsonByteNoBase64(tamperedHmac)
    // Result will have Valid: false
    ```

## Running the Example

To run this example:

```bash
cd go-sdk/docs/examples/create_hmac
go mod tidy
go run create_hmac.go
```

## Key Concepts

-   **HMAC (Hash-based Message Authentication Code)**: Provides data integrity and authenticity using a shared secret key.
-   **`wallet.CreateHmacArgs` / `wallet.VerifyHmacArgs`**: Structs for HMAC creation/verification parameters.
-   **`EncryptionArgs`**: Embedded in the above, contains `ProtocolID`, `KeyID`, and `Counterparty` which collectively define the context for deriving the HMAC key.
-   **`KeyID`**: Mandatory identifier for keying material. Length must be >= 1 character.
-   **`ProtocolID.Protocol`**: String identifying the protocol. Length must be >= 5 chars, containing only letters, numbers, and spaces.
-   **`CounterpartyTypeSelf`**: Used in `EncryptionArgs.Counterparty.Type` when a wallet creates or verifies an HMAC for its own context.

## Additional Resources

-   [go-sdk `wallet` package documentation](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/wallet)
-   SDK tests, particularly `wallet/wallet_test.go` (`TestHmacCreateVerify`), provide further examples.
