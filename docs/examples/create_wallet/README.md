# Create Wallet Example

This example demonstrates how to use the `compat/bip39`, `compat/bip32`, and `wallet` packages to create a new BSV Hierarchical Deterministic (HD) wallet and derive keys.

## Overview

The process involves several steps:
1. Generating cryptographic entropy.
2. Creating a mnemonic phrase from the entropy using BIP39.
3. Generating a seed from the mnemonic using BIP39.
4. Creating a master extended private key (xPriv) from the seed using BIP32.
5. Optionally, creating a `wallet.Wallet` instance from a private key (e.g., the master private key or a derived one).
6. Deriving child extended keys using a BIP44 path from the master extended key.
7. Extracting private keys, public keys, and addresses from the derived keys.

## Example Overview

This example demonstrates:

1. Generating entropy.
2. Creating a 12-word mnemonic.
3. Generating a seed from the mnemonic.
4. Creating a master extended private key (`xPriv`).
5. Creating a `wallet.Wallet` instance (using the master private key for demonstration).
6. Deriving a child key at path `m/44'/0'/0'/0/0`.
7. Getting the private key, public key, and P2PKH address for the derived key in two ways:
    a. From the derived `*ec.PrivateKey` and `*ec.PublicKey`.
    b. Directly from the derived `*bip32.ExtendedKey`.

## Code Walkthrough

### Generating Entropy and Mnemonic

```go
// Generate entropy for the mnemonic
entropy, err := bip39.NewEntropy(128) // 128 bits for a 12-word mnemonic

// Generate a new 12-word mnemonic from the entropy
mnemonic, err := bip39.NewMnemonic(entropy)
```
First, we generate 128 bits of entropy. Then, we use this entropy to create a standard 12-word BIP39 mnemonic phrase.

### Generating Seed and Master Key

```go
// Generate a seed from the mnemonic
seed := bip39.NewSeed(mnemonic, "") // Empty passphrase for this example

// Create a new master extended key from the seed
masterKey, err := bip32.NewMaster(seed, &chaincfg.MainNet)
```
Next, the mnemonic is converted into a seed. This seed is then used to generate the master extended private key (`xPriv`) for the main Bitcoin network, following BIP32.

### Creating a Wallet Instance

```go
// Create a wallet instance from the master private key
masterPrivKey, err := masterKey.ECPrivKey()
w, err := wallet.NewWallet(masterPrivKey)
```
An `ExtendedKey` contains a private key. We extract this `*ec.PrivateKey` and use it to initialize a `wallet.Wallet` instance. This step demonstrates how a wallet object can be created, though for deriving keys, we'll primarily use the `ExtendedKey`.

### Deriving a Child Key

```go
// Define a derivation path (e.g., m/44'/0'/0'/0/0 for the first external address)
derivationPathStr := "m/44'/0'/0'/0/0"

// Derive the child key using the masterKey (ExtendedKey)
derivedKey, err := masterKey.DeriveChildFromPath(derivationPathStr)
```
Using the master extended key, we derive a child key according to the specified BIP44 derivation path.

### Getting Keys and Addresses

```go
// Get the private key from the derived extended key
privateKey, err := derivedKey.ECPrivKey()
fmt.Printf("Derived Private Key (Hex): %x\n", privateKey.Serialize())

// Get the public key from the private key
publicKey := privateKey.PubKey()
fmt.Printf("Derived Public Key (Hex): %x\n", publicKey.Compressed())

// Get the P2PKH address from the public key
addressFromPubKey, _ := script.NewAddressFromPublicKey(publicKey, true)
fmt.Printf("Address from Public Key: %s\n", addressFromPubKey.AddressString)

// You can also get the address directly from the derived extended key
addressFromExtendedKey := derivedKey.Address(&chaincfg.MainNet)
fmt.Printf("Address from Derived Extended Key: %s\n", addressFromExtendedKey)
```
From the derived `ExtendedKey`, we extract the `*ec.PrivateKey`. From this private key, we can obtain its hexadecimal representation, the corresponding `*ec.PublicKey` (and its compressed hex form), and finally, the P2PKH address using the `script` package.

Alternatively, the `ExtendedKey` itself provides a direct method to get the P2PKH address for a given network.

## Running the Example

To run this example:

```bash
cd go-sdk/docs/examples/create_wallet
go mod tidy
# (if you haven't run it before or added new imports in other examples)
go run create_wallet.go
```

**Note**: Each run will generate a new, unique wallet. Store your mnemonic phrase and/or master extended private key (xPriv) securely if you intend to use the generated wallet.

## Key Concepts

- **BIP39**: Bitcoin Improvement Proposal for mnemonic code for generating deterministic keys.
- **BIP32**: Bitcoin Improvement Proposal for hierarchical deterministic wallets (HD Wallets).
- **BIP44**: Defines a path convention for HD wallets (e.g., `m / purpose' / coin_type' / account' / change / address_index`).
- **Entropy**: Random data used as a source for generating mnemonics.
- **Mnemonic**: A human-readable sequence of words representing the master seed.
- **Seed**: Derived from the mnemonic, used to generate the master key.
- **Extended Key (xPriv/xPub)**: A key that can be used to derive child keys in an HD wallet. `xPriv` for private, `xPub` for public.
- **Derivation Path**: A structured path used to derive specific child keys.
- **Private Key**: A secret number that allows spending of bitcoins.
- **Public Key**: Derived from a private key, used to receive bitcoins.
- **Address**: A user-friendly representation of a public key for transactions.

## Additional Resources

- [go-sdk `wallet` package](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/wallet)
- [go-sdk `compat/bip32` package](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/compat/bip32)
- [go-sdk `compat/bip39` package](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/compat/bip39)
- [go-sdk `primitives/ec` package](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/primitives/ec)
- [go-sdk `script` package](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/script)
