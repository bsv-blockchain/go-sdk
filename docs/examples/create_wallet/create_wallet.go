package main

import (
	"fmt"
	"log"

	"github.com/bsv-blockchain/go-sdk/script"

	bip32 "github.com/bsv-blockchain/go-sdk/compat/bip32"
	"github.com/bsv-blockchain/go-sdk/compat/bip39"
	chaincfg "github.com/bsv-blockchain/go-sdk/transaction/chaincfg"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func main() {
	// Generate entropy for the mnemonic
	fmt.Println("Generating entropy for mnemonic...")
	entropy, err := bip39.NewEntropy(128) // 128 bits for a 12-word mnemonic
	if err != nil {
		log.Fatalf("Failed to generate entropy: %v", err)
	}

	// Generate a new 12-word mnemonic from the entropy
	fmt.Println("Generating a new mnemonic...")
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		log.Fatalf("Failed to generate mnemonic: %v", err)
	}
	fmt.Printf("Generated Mnemonic: %s\n\n", mnemonic)

	// Generate a seed from the mnemonic
	// An empty password is used for simplicity in this example
	fmt.Println("Generating seed from mnemonic...")
	seed := bip39.NewSeed(mnemonic, "")

	// Create a new master extended key from the seed
	fmt.Println("Creating master extended key...")
	masterKey, err := bip32.NewMaster(seed, &chaincfg.MainNet)
	if err != nil {
		log.Fatalf("Failed to create master key: %v", err)
	}
	fmt.Printf("Master Private Key (xPriv): %s\n", masterKey.String())

	// Create a wallet instance from the master private key
	// Note: The wallet instance itself doesn't store the mnemonic or master xPriv directly for this example
	// It would typically be initialized with a specific private key derived for an identity.
	// For simplicity, we'll use the master private key to demonstrate wallet creation.
	fmt.Println("\nCreating wallet instance (using master private key for this example)...")
	masterPrivKey, err := masterKey.ECPrivKey()
	if err != nil {
		log.Fatalf("Failed to get master private key for wallet: %v", err)
	}
	w, err := wallet.NewWallet(masterPrivKey)
	if err != nil {
		log.Fatalf("Failed to create wallet: %v", err)
	}
	_ = w // Wallet instance created, assign to _ to satisfy linter for this example
	fmt.Println("Wallet instance created.")

	// Define a derivation path
	// m/44'/0'/0'/0/0 is a standard BIP44 path for the first external address
	// The "m/" prefix is a convention, remove it for DeriveChildFromPath
	derivationPathStr := "44'/0'/0'/0/0"
	fmt.Printf("\nDeriving key for path: m/%s\n", derivationPathStr)

	// Derive the child key using the masterKey (ExtendedKey)
	// The DeriveChildFromPath method handles string paths.
	derivedKey, err := masterKey.DeriveChildFromPath(derivationPathStr)
	if err != nil {
		log.Fatalf("Failed to derive key for path %s: %v", derivationPathStr, err)
	}

	// Get the private key from the derived extended key
	privateKey, err := derivedKey.ECPrivKey()
	if err != nil {
		log.Fatalf("Failed to get derived private key: %v", err)
	}
	fmt.Printf("Derived Private Key (Hex): %x\n", privateKey.Serialize())

	// Get the public key from the private key
	publicKey := privateKey.PubKey()
	fmt.Printf("Derived Public Key (Hex): %x\n", publicKey.Compressed())

	// Get the P2PKH address from the public key
	// This is one way to get the address.
	addressFromPubKey, _ := script.NewAddressFromPublicKey(publicKey, false)
	fmt.Printf("Address from Public Key: %s\n\n", addressFromPubKey.AddressString)

	// You can also get the address directly from the derived extended key
	// This is another way, often more direct if you have the ExtendedKey.
	addressFromExtendedKey := derivedKey.Address(&chaincfg.MainNet)
	fmt.Printf("Address from Derived Extended Key: %s\n\n", addressFromExtendedKey)

	fmt.Println("Wallet creation and key derivation complete.")
	fmt.Println("IMPORTANT: Store your mnemonic phrase securely. This example generates a new wallet on each run.")
	fmt.Printf("To use this wallet, you would typically persist the mnemonic or the master extended private key (xPriv: %s).\n", masterKey.String())
}
