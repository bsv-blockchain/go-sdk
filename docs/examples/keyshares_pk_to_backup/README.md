# Private Key to Backup Shares Example

This example demonstrates how to use the `ec` package to split a private key into multiple backup shares using Shamir's Secret Sharing.

## Overview

The `keyshares_pk_to_backup` example (using `to_backup.go`) showcases:
1. Starting with a private key (from a WIF string).
2. Defining the total number of shares to create and the threshold required for reconstruction.
3. Using `ec.PrivateKey.ToBackupShares` to generate the shares.
4. Printing the generated shares.

## Code Walkthrough

### Generating Key Shares

```go
pk, _ := ec.PrivateKeyFromWif("KxPEP4DCP2a4g3YU5amfXjFH4kWmz8EHWrTugXocGWgWBbhGsX7a")
log.Println("Private key:", hex.EncodeToString(pk.PubKey().Hash())[:8])
totalShares := 5
threshold := 3
shares, _ := pk.ToBackupShares(threshold, totalShares)

for i, share := range shares {
    log.Printf("Share %d: %s", i+1, share)
}
```

This section shows how to load a private key from its WIF representation and then call `ToBackupShares` with the desired number of total shares and the minimum threshold of shares needed to reconstruct the original key. The resulting share strings are then printed. Each share string contains the share value, the threshold, and an identifier.

## Running the Example

To run this example:

```bash
go run to_backup.go
```

The output will display the identifier of the private key and the generated shares.

**Note**: The example uses a predefined WIF string. The generated shares are suitable for backup purposes. To reconstruct the private key, a minimum of `threshold` shares must be provided to `ec.PrivateKeyFromBackupShares`.

## Integration Steps

To integrate this functionality into your application:
1. Obtain or generate an `*ec.PrivateKey` object.
2. Determine the desired `totalShares` and `threshold` for your backup strategy. A higher threshold increases security but requires more shares for recovery.
3. Call `privateKey.ToBackupShares(threshold, totalShares)` to get an array of share strings.
4. Securely distribute and store these shares in different locations.

## Additional Resources

For more information, see:
- [Package Documentation](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/primitives/ec)
- [Private Key From Backup Shares Example](../keyshares_pk_from_backup/)
