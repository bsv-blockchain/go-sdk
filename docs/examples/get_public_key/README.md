# Get Public Key Example

This example demonstrates how to use the `wallet` package to retrieve various types of public keys associated with a wallet.

## Overview

The `wallet.Wallet` can manage multiple cryptographic keys. The `GetPublicKey` method allows you to retrieve:
1.  **Identity Public Key**: The root public key of the wallet itself.
2.  **Derived Public Key (Self)**: A public key derived for a specific protocol and key ID, intended for the wallet's own use (e.g., for self-encryption or signing).
3.  **Derived Public Key (for Counterparty)**: A public key derived by the user's wallet that is specifically for interacting with a known counterparty. This is often used in shared secret generation schemes like ECIES.

## Example Overview

This example demonstrates:

1.  Creating a user's wallet.
2.  Retrieving the user's identity public key.
3.  Retrieving a public key derived by the user's wallet for its own use under a specific protocol and key ID.
4.  Simulating a counterparty and retrieving a public key derived by the user's wallet for interacting with that counterparty under a specific protocol and key ID.

## Code Walkthrough

### 1. Setup User Wallet

```go
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"log"

	"github.com/bsv-blockchain/go-sdk/wallet"
)

func main() {
	ctx := context.Background()

	// Generate a new private key for the user
	userKey, err := ec.NewPrivateKey()
	if err != nil {
		log.Fatalf("Failed to generate user private key: %v", err)
	}
	log.Printf("User private key: %s", userKey.Wif())

	// Create a new wallet for the user
	userWallet, err := wallet.NewWallet(userKey)
	if err != nil {
		log.Fatalf("Failed to create user wallet: %v", err)
	}
	log.Println("User wallet created successfully.")
```
First, we initialize a new wallet for the user.

### 2. Get User's Identity Public Key

```go
	// --- Get User's Own Public Key (Identity Key) ---
	identityPubKeyArgs := wallet.GetPublicKeyArgs{
		IdentityKey: true, // Indicates we want the root identity public key of the wallet
	}
	identityPubKeyResult, err := userWallet.GetPublicKey(ctx, identityPubKeyArgs, "example-app")
	if err != nil {
		log.Fatalf("Failed to get user's identity public key: %v", err)
	}
	fmt.Printf("User's Identity Public Key: %s\n", hex.EncodeToString(identityPubKeyResult.PublicKey.Compressed()))
```
To get the wallet's own root identity public key, we set `IdentityKey: true` in `GetPublicKeyArgs`.

### 3. Get User's Derived Public Key for Self

```go
	// --- Get User's Derived Public Key for a Protocol/KeyID (Self) ---
	// Define a protocol and key ID for deriving a key
	selfProtocol := wallet.Protocol{
		SecurityLevel: wallet.SecurityLevelEveryApp, // Or other appropriate security level
		Protocol:      "myprotocol",
	}
	selfKeyID := "user001"

	getSelfPubKeyArgs := wallet.GetPublicKeyArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: selfProtocol,
			KeyID:      selfKeyID,
			Counterparty: wallet.Counterparty{
				Type: wallet.CounterpartyTypeSelf, // Explicitly for self
			},
		},
	}
	selfPubKeyResult, err := userWallet.GetPublicKey(ctx, getSelfPubKeyArgs, "example-app")
	if err != nil {
		log.Fatalf("Failed to get user's derived public key (self): %v", err)
	}
	fmt.Printf("User's Derived Public Key (Self - Protocol: %s, KeyID: %s): %s\n",
		selfProtocol.Protocol, selfKeyID, hex.EncodeToString(selfPubKeyResult.PublicKey.Compressed()))
```
To derive a public key for the wallet's own use under a specific protocol and key ID, we set `Counterparty.Type` to `wallet.CounterpartyTypeSelf`.

### 4. Get Derived Public Key for a Counterparty

```go
	// --- Get Counterparty's Public Key ---
	// Generate a new private key for the counterparty
	counterpartyKey, err := ec.NewPrivateKey()
	if err != nil {
		log.Fatalf("Failed to generate counterparty private key: %v", err)
	}
	log.Printf("Counterparty private key: %s", counterpartyKey.Wif())

	// Define a protocol and key ID for deriving a key with a counterparty
	counterpartyProtocol := wallet.Protocol{
		SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
		Protocol:      "sharedprotocol",
	}
	counterpartyKeyID := "sharedkey001"

	getCounterpartyPubKeyArgs := wallet.GetPublicKeyArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: counterpartyProtocol,
			KeyID:      counterpartyKeyID,
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: counterpartyKey.PubKey(), // The counterparty's public key
			},
		},
		// ForSelf: false, // This is the default, meaning we want the public key *for* the counterparty
	}

	// User's wallet gets the public key it would use to interact with the counterparty
	derivedForCounterpartyPubKeyResult, err := userWallet.GetPublicKey(ctx, getCounterpartyPubKeyArgs, "example-app")
	if err != nil {
		log.Fatalf("Failed to get derived public key for counterparty: %v", err)
	}
	fmt.Printf("User's Derived Public Key (for Counterparty - Protocol: %s, KeyID: %s): %s\n",
		counterpartyProtocol.Protocol, counterpartyKeyID, hex.EncodeToString(derivedForCounterpartyPubKeyResult.PublicKey.Compressed()))

	log.Println("Successfully retrieved public keys.")
}
```
To get a public key derived by the user's wallet for interaction with a specific counterparty, we set `Counterparty.Type` to `wallet.CounterpartyTypeOther` and provide the `Counterparty.Counterparty` public key. The `ForSelf` field in `GetPublicKeyArgs` defaults to `false`, indicating the derived key is for the counterparty.

## Running the Example

To run this example:

```bash
cd go-sdk/docs/examples/get_public_key
go mod tidy
go run get_public_key.go
```

## Key Concepts

- **`wallet.GetPublicKeyArgs`**: Struct used to specify parameters for retrieving public keys.
- **`IdentityKey`**: Boolean flag in `GetPublicKeyArgs`. If true, retrieves the wallet's root identity public key.
- **`EncryptionArgs`**: Embedded in `GetPublicKeyArgs`, used for deriving keys based on protocol, key ID, and counterparty.
- **`CounterpartyTypeSelf`**: Used in `EncryptionArgs.Counterparty.Type` to derive a key for the wallet's own use.
- **`CounterpartyTypeOther`**: Used in `EncryptionArgs.Counterparty.Type` along with the counterparty's public key to derive a key for interacting with that counterparty.
- **`ForSelf`**: Field in `GetPublicKeyArgs` (defaults to `false`). When `false` and `CounterpartyTypeOther` is used, it means the public key derived is the one the user's wallet would use for the specified counterparty (e.g., as a component in an ECIES shared secret calculation).

## Additional Resources

- [go-sdk `wallet` package documentation](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/wallet)
