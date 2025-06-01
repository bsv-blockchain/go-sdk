# Get Public Key Example

This example demonstrates how to retrieve a public key from a wallet. It covers scenarios for retrieving the user's own public key and a counterparty's public key.

## Running the Example

To run this example, navigate to the `go-sdk/docs/examples/get_public_key` directory and execute the following command:

```bash
go run get_public_key.go
```

## Code

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func main() {
	ctx := context.Background()

	// Generate a new private key for the user
	userKey, err := ec.NewPrivateKey()
	if err != nil {
		log.Fatalf("Failed to generate user private key: %v", err)
	}
	log.Printf("User private key: %s", userKey.SerialiseWIF())

	// Create a new wallet for the user
	userWallet, err := wallet.NewWallet(userKey)
	if err != nil {
		log.Fatalf("Failed to create user wallet: %v", err)
	}
	log.Println("User wallet created successfully.")

	// --- Get User's Own Public Key (Identity Key) ---
	identityPubKeyArgs := wallet.GetPublicKeyArgs{
		IdentityKey: true, // Indicates we want the root identity public key of the wallet
	}
	identityPubKeyResult, err := userWallet.GetPublicKey(ctx, identityPubKeyArgs, "example-app")
	if err != nil {
		log.Fatalf("Failed to get user's identity public key: %v", err)
	}
	fmt.Printf("User's Identity Public Key: %s\n", identityPubKeyResult.PublicKey.SerialiseCompressed())

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
		selfProtocol.Protocol, selfKeyID, selfPubKeyResult.PublicKey.SerialiseCompressed())

	// --- Get Counterparty's Public Key ---
	// Generate a new private key for the counterparty
	counterpartyKey, err := ec.NewPrivateKey()
	if err != nil {
		log.Fatalf("Failed to generate counterparty private key: %v", err)
	}
	log.Printf("Counterparty private key: %s", counterpartyKey.SerialiseWIF())

	// (Optional) Create a wallet for the counterparty - not strictly needed for this example part,
	// but useful if the counterparty wallet needs to perform actions.
	// counterpartyWallet, err := wallet.NewWallet(counterpartyKey)
	// if err != nil {
	//  log.Fatalf("Failed to create counterparty wallet: %v", err)
	// }

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
		counterpartyProtocol.Protocol, counterpartyKeyID, derivedForCounterpartyPubKeyResult.PublicKey.SerialiseCompressed())

	log.Println("Successfully retrieved public keys.")
}

```

### Explanation

1.  **Setup**:
    *   We import necessary packages: `context`, `fmt` for printing, `log` for error handling, `ec` for elliptic curve cryptography (key generation), and `wallet` for wallet operations.
    *   A `context.Background()` is created.

2.  **User Wallet and Identity Key**:
    *   A new private key (`userKey`) is generated using `ec.NewPrivateKey()`.
    *   A `wallet.NewWallet` is initialized using this `userKey`.
    *   To get the user's own root identity public key, `userWallet.GetPublicKey` is called with `wallet.GetPublicKeyArgs{IdentityKey: true}`. The `PublicKey` field in the result contains the public key.

3.  **User's Derived Public Key (Self)**:
    *   We define a `wallet.Protocol` and a `keyID`. These are used to derive specific keys for different applications or purposes.
    *   `userWallet.GetPublicKey` is called with `EncryptionArgs` specifying the `ProtocolID`, `KeyID`, and `Counterparty` set to `wallet.CounterpartyTypeSelf`. This tells the wallet to derive a public key for the user themselves under that protocol and key ID.

4.  **Counterparty Public Key**:
    *   A new private key (`counterpartyKey`) is generated for a simulated counterparty. In a real application, you would typically receive the counterparty's public key through other means.
    *   We define another `wallet.Protocol` and `keyID` that might be used for shared interactions.
    *   `userWallet.GetPublicKey` is called again. This time, `EncryptionArgs.Counterparty` is set to `wallet.CounterpartyTypeOther` and `Counterparty: counterpartyKey.PubKey()`.
    *   The `ForSelf` field in `GetPublicKeyArgs` is `false` by default. This means the call retrieves the public key that `userWallet` would use when interacting *with* the specified counterparty under the given protocol and key ID. This is typically part of an ECDH key agreement process.

The example prints the WIF private keys (for demonstration; handle private keys securely in real applications) and the compressed public keys obtained in each scenario.
