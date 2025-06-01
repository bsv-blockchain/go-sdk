# Generate HD Key Pair Example

This example demonstrates how to use the `bip32` compatibility package to generate a new Hierarchical Deterministic (HD) key pair (xPriv and xPub).

## Overview

The `generate_hd_key` example showcases:
1. Calling `bip32.GenerateHDKeyPair` with a specified seed length (`bip32.SecureSeedLength`).
2. Receiving the generated extended private key (xPriv) and extended public key (xPub).
3. Printing both keys.

## Code Walkthrough

### Generating the HD Key Pair

```go
// Generate a new HD key pair (xPriv and xPub)
// bip32.SecureSeedLength provides a recommended length for the seed.
xPrivateKey, xPublicKey, err := bip32.GenerateHDKeyPair(bip32.SecureSeedLength)
if err != nil {
    log.Fatalf("Error generating HD key pair: %s", err.Error())
}

// Print the generated keys
log.Printf("xPrivateKey: %s\n", xPrivateKey)
log.Printf("xPublicKey: %s\n", xPublicKey)
```

This section shows the direct use of `bip32.GenerateHDKeyPair`. This function creates a new master HD key from a randomly generated seed of the given length. It returns the extended private key (xPriv) and the corresponding extended public key (xPub) as strings.

## Running the Example

To run this example:

```bash
go run generate_hd_key.go
```
The output will be the newly generated xPrivateKey and xPublicKey strings. Each run will produce a different key pair.

**Note**:
- The generated xPrivateKey is the master private key for an HD wallet structure. It should be kept extremely secure.
- The xPublicKey can be used to derive child public keys without exposing the private key.
- `bip32.SecureSeedLength` is typically 32 bytes (256 bits) or 64 bytes (512 bits) for strong security.

## Integration Steps

To generate a new HD key pair in your application:
1. Call `xPriv, xPub, err := bip32.GenerateHDKeyPair(seedLength)`, where `seedLength` is your desired seed length (e.g., `bip32.SecureSeedLength` or `bip32.RecommendedSeedLen`).
2. Handle any potential error during generation.
3. Securely store the `xPriv` string. The `xPub` string can be stored less securely if needed for public key derivation.
4. You can then use the `xPriv` or `xPub` with functions like `bip32.GetHDKeyFromExtendedPrivateKey()` or `bip32.GetHDKeyFromExtendedPublicKey()` to get `*bip32.HDKey` objects, which can then be used to derive child keys.

## Additional Resources

For more information, see:
- [Package Documentation - BIP32 compatibility](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/compat/bip32)
- [BIP32 Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [Derive Child Key Example](../derive_child/) (Note: this example uses a different derivation method, `ec.PrivateKey.DeriveChild`, not directly HD path derivation from an xPriv/xPub but is related to key derivation)
- [HD Key From xPub Example](../hd_key_from_xpub/)
