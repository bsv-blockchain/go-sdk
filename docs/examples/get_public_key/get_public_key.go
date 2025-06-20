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

	// --- Get User's Own Public Key (Identity Key) ---
	identityPubKeyArgs := wallet.GetPublicKeyArgs{
		IdentityKey: true, // Indicates we want the root identity public key of the wallet
	}
	identityPubKeyResult, err := userWallet.GetPublicKey(ctx, identityPubKeyArgs, "example-app")
	if err != nil {
		log.Fatalf("Failed to get user's identity public key: %v", err)
	}
	fmt.Printf("User's Identity Public Key: %s\n", hex.EncodeToString(identityPubKeyResult.PublicKey.Compressed()))

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

	// --- Get Counterparty's Public Key ---
	// Generate a new private key for the counterparty
	counterpartyKey, err := ec.NewPrivateKey()
	if err != nil {
		log.Fatalf("Failed to generate counterparty private key: %v", err)
	}
	log.Printf("Counterparty private key: %s", counterpartyKey.Wif())

	// (Optional) Create a wallet for the counterparty - not strictly needed for this example part,
	// but useful if the counterparty wallet needs to perform actions.
	// counterpartyWallet, err := wallet.NewWallet(counterpartyKey)
	// if err != nil {
	// 	log.Fatalf("Failed to create counterparty wallet: %v", err)
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
		counterpartyProtocol.Protocol, counterpartyKeyID, hex.EncodeToString(derivedForCounterpartyPubKeyResult.PublicKey.Compressed()))

	log.Println("Successfully retrieved public keys.")
}
