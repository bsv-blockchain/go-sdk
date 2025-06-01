# HD Key From xPub Example

This example demonstrates how to use the `bip32` compatibility package to convert an extended public key (xPub) string into an HD (Hierarchical Deterministic) key object.

## Overview

The `hd_key_from_xpub` example showcases:
1. Starting with a standard xPub string.
2. Using `bip32.GetHDKeyFromExtendedPublicKey` to parse the xPub.
3. Verifying the properties of the resulting HD key object.

## Code Walkthrough

### Converting xPub to HD Key

```go
// Start with an existing xPub
xPub := "xpub661MyMwAqRbcH3WGvLjupmr43L1GVH3MP2WQWvdreDraBeFJy64Xxv4LLX9ZVWWz3ZjZkMuZtSsc9qH9JZR74bR4PWkmtEvP423r6DJR8kA"

// Convert to a HD key
key, err := bip32.GetHDKeyFromExtendedPublicKey(xPub)
if err != nil {
    log.Fatalf("error occurred: %s", err.Error())
}

log.Printf("converted key: %s private: %v", key.String(), key.IsPrivate())
```

This section shows the direct conversion of an xPub string into an `*bip32.HDKey` object. The `IsPrivate()` method will return `false` for keys derived from an xPub.

## Running the Example

To run this example:

```bash
go run hd_key_from_xpub.go
```

**Note**: This example uses a predefined xPub string. You can replace it with any valid xPub to see the conversion.

## Integration Steps

To integrate this functionality into your application:
1. Obtain an xPub string that you need to work with.
2. Use `bip32.GetHDKeyFromExtendedPublicKey(xPubString)` to get an HD key object.
3. You can then use this HD key object to derive child public keys.

## Additional Resources

For more information, see:
- [Package Documentation](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/compat/bip32)
- [Generate HD Key Example](../generate_hd_key/)
- [Derive Child Key Example](../derive_child/)