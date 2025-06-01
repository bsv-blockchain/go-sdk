# Verify BEEF Example

This example demonstrates how to use the `transaction` and `spv` packages to perform a basic verification of a BEEF (Bitcoin Extended Envelope Format) data structure.

## Overview

The `verify_beef` example showcases:
1. Starting with a hexadecimal string representing BEEF data.
2. Creating a `transaction.Transaction` object from this hex string using `transaction.NewTransactionFromBEEFHex`.
3. Accessing the `MerklePath` from the transaction.
4. Calling the `merklePath.Verify` method to check the internal consistency of the Merkle proof against the transaction ID.
5. Using `spv.GullibleHeadersClient` as a placeholder for header validation (it trusts any header).

## Code Walkthrough

### Verifying the Merkle Path in BEEF

```go
// BEEF data as a hex string (truncated for brevity)
const BEEFHex = "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000"

// Create transaction from BEEF hex
tx, err := transaction.NewTransactionFromBEEFHex(BEEFHex)
if err != nil {
    panic(err)
}

// Verify the MerklePath
// This checks if the path correctly hashes to a Merkle root that
// would be consistent with the block header (if the header was known and trusted).
// GullibleHeadersClient trusts any header, so this mainly checks path integrity.
verified, _ := tx.MerklePath.Verify(tx.TxID(), &spv.GullibleHeadersClient{})
println(verified)
```

This section demonstrates loading a transaction from its BEEF hex representation. The `merklePath.Verify` method is then called. This method performs several checks:
- It computes the Merkle root from the provided path and transaction ID.
- It then (conceptually) asks the `spv.Headers` client (here, `GullibleHeadersClient`) if this computed root is valid for the block height specified in the Merkle path.

Since `GullibleHeadersClient` always returns `true` (it "trusts" any header it's asked about), the `verified` result primarily indicates whether the Merkle path itself is internally consistent and correctly reconstructs *a* Merkle root for the given transaction ID. It does not, with this client, confirm that this root matches an *actual* block header from the blockchain.

## Running the Example

To run this example:

```bash
go run verify_beef.go
```

The output will be `true` if the Merkle path within the BEEF is internally consistent and correctly computes a Merkle root for the transaction ID.

**Note**:
- The example uses a hardcoded BEEF hex string.
- `spv.GullibleHeadersClient` is used for simplicity. In a real SPV client, you would use a `headers_client.Client` configured to connect to a real headers service (like TAAL MAPI) to fetch and validate against actual block headers.
- The `merklePath.Verify` method, when used with a proper `spv.Headers` implementation, provides a more complete SPV check by confirming the transaction's inclusion in a specific block that is part of the longest chain.

## Integration Steps

To integrate BEEF verification into your application:
1. Obtain the BEEF data for the transaction, typically in hex or binary format.
2. Create a `transaction.Transaction` object using `transaction.NewTransactionFromBEEFHex()` or `transaction.NewTransactionFromBEEF()`.
3. To perform a full SPV check, initialize a `headers_client.Client` pointing to a trusted headers service.
4. Call `tx.MerklePath.Verify(tx.TxID(), yourHeadersClient)`.
   - A `true` result indicates that the transaction is confirmed in a block whose header is known and trusted by your `headersClient`.
   - A `false` result or an error indicates a problem with the proof or that the transaction is not confirmed according to the `headersClient`.

## Additional Resources

For more information, see:
- [Package Documentation - Transaction](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/transaction)
- [Package Documentation - SPV](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/spv)
- [Package Documentation - Headers Client](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/transaction/chaintracker/headers_client)
- [Validate SPV Example](../validate_spv/)
