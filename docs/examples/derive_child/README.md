# Derive Child Key Example

This example demonstrates how to use the `ec` package to derive a child private key from a parent private key, a counterparty's public key, and an invoice number. This method is often associated with BRC-42 key derivations for creating unique keys per interaction or transaction.

## Overview

The `derive_child` example showcases:
1. Starting with a parent private key (e.g., a merchant's private key).
2. Using a counterparty's public key (e.g., a customer's public key).
3. Using a unique identifier for the interaction (e.g., an invoice number).
4. Calling `parentPrivateKey.DeriveChild()` to generate the child private key.
5. Serializing the derived child private key.

## Code Walkthrough

### Deriving the Child Key

```go
// Parent private key (e.g., merchant's key)
merchantPrivKey, _ := ec.PrivateKeyFromWif("L4PoBVNHZb9wVs9TFqyFrKxmpkJPPyzbjQrCiiQUoCz7ceAq63Rt")

// Unique identifier for the interaction
invoiceNum := "test invoice number"

// Counterparty's public key (e.g., customer's public key)
customerPubKeyStr := "03121a7afe56fc8e25bca4bb2c94f35eb67ebe5b84df2e149d65b9423ee65b8b4b"
customerPubKey, _ := ec.PublicKeyFromString(customerPubKeyStr)

// Derive the child private key
child, _ := merchantPrivKey.DeriveChild(customerPubKey, invoiceNum)

fmt.Printf("%x", child.Serialize())
// The 'child' private key can now be used for signing specific to this interaction
```

This section shows loading a merchant's private key and a customer's public key. Along with an invoice number, these are used in the `DeriveChild` method to compute a new, unique private key. This child key can then be used for operations related specifically to that customer and invoice, without exposing the parent merchant key.

## Running the Example

To run this example:

```bash
go run derive_child.go
```
The output will be the hexadecimal representation of the serialized child private key.

**Note**:
- The example uses hardcoded WIF and public key strings. In a real application, these would be dynamically obtained.
- The `invoiceNum` (or any unique string/bytes) ensures that even with the same merchant and customer keys, a different child key can be derived for each distinct interaction.
- This method is useful for generating per-transaction or per-user keys without needing to manage a vast number of unrelated private keys.

## Integration Steps

To integrate child key derivation into your application:
1. Obtain the parent private key (e.g., your service's master private key for a particular purpose).
2. Obtain the counterparty's public key relevant to the interaction.
3. Generate a unique identifier for the interaction (e.g., invoice ID, session ID).
4. Call `parentPrivateKey.DeriveChild(counterpartyPubKey, uniqueIdentifier)` to get the `*ec.PrivateKey` for the child.
5. Use this child private key for signing or other cryptographic operations specific to that interaction.

## Additional Resources

For more information, see:
- [Package Documentation - EC](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/primitives/ec)
- BRC-42 (or similar key derivation scheme) specifications if this aligns with a specific standard you are following.
- [Generate HD Key Example](../generate_hd_key/)
- [HD Key From xPub Example](../hd_key_from_xpub/)
