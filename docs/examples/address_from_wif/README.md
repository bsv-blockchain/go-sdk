# Address From WIF Example

This example demonstrates how to derive a Bitcoin SV address from a Wallet Import Format (WIF) private key string using the `ec` and `script` packages.

## Overview

The `address_from_wif` example showcases:
1. Importing a private key from its WIF string representation using `ec.PrivateKeyFromWif`.
2. Getting the corresponding public key from the private key using `privateKey.PubKey()`.
3. Generating a P2PKH (Pay-to-Public-Key-Hash) address object from this public key using `script.NewAddressFromPublicKey`.
4. Printing the serialized private key, the string representation of the derived address, and its public key hash.

## Code Walkthrough

### Deriving Address from WIF

```go
// Import private key from WIF string
privKey, _ := ec.PrivateKeyFromWif("Kxfd8ABTYZHBH3y1jToJ2AUJTMVbsNaqQsrkpo9gnnc1JXfBH8mn")

// Log the serialized private key (hexadecimal)
log.Printf("Private key (hex): %x\n", privKey.Serialize())

// Get the public key associated with the private key
pubKey := privKey.PubKey()

// Create a new address object from the public key
// The 'true' argument typically indicates if it's for mainnet (compressed pubkey used for address)
address, _ := script.NewAddressFromPublicKey(pubKey, true)

// Print the address string and the underlying public key hash
fmt.Printf("Address: %s\n", address.AddressString)
fmt.Printf("Public Key Hash: %s\n", address.PublicKeyHash) // Or however you wish to display the hash
```

This section shows the step-by-step process:
- `ec.PrivateKeyFromWif` parses the WIF string and returns an `*ec.PrivateKey` object.
- `privKey.PubKey()` returns the corresponding `*ec.PublicKey`.
- `script.NewAddressFromPublicKey(pubKey, true)` takes the public key and a boolean (often indicating network or if the key should be compressed for address generation) to produce an `*script.Address` object. This object contains the familiar base58check encoded address string and the raw public key hash.

## Running the Example

To run this example:

```bash
go run address_from_wif.go
```
The output will display the hexadecimal representation of the private key, the derived P2PKH address string, and the public key hash component of the address.

**Note**:
- The WIF string is hardcoded. In a real application, this would come from a secure source.
- The example derives a P2PKH address, which is the most common address type.
- The boolean argument `true` in `NewAddressFromPublicKey` typically signifies that the address should be generated for the main network, often implying the use of a compressed public key for the hash.

## Integration Steps

To derive an address from a WIF in your application:
1. Obtain the WIF string for the private key.
2. Use `priv, err := ec.PrivateKeyFromWif(wifString)` to get the private key object. Handle any errors.
3. Get the public key: `pubKey := priv.PubKey()`.
4. Generate the address: `addr, err := script.NewAddressFromPublicKey(pubKey, isMainnet)`, where `isMainnet` is true for mainnet addresses. Handle errors.
5. You can then use `addr.AddressString` for display or in transactions, and `addr.PublicKeyHash` if you need the raw hash.

## Additional Resources

For more information, see:
- [Package Documentation - EC primitives](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/primitives/ec)
- [Package Documentation - Script](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/script)
- [Generate HD Key Example](../generate_hd_key/) (for creating master keys from which WIFs can be derived)
