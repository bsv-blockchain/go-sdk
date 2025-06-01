# Verify Transaction (using SPV and BEEF) Example

This example demonstrates how to use the `spv` and `transaction` packages to perform a comprehensive verification of a transaction, including its scripts and Merkle proof (from BEEF data).

## Overview

The `verify_transaction` example showcases:
1. Starting with a hexadecimal string representing BEEF data (which includes the transaction and its Merkle path).
2. Creating a `transaction.Transaction` object from this hex string using `transaction.NewTransactionFromBEEFHex`.
3. Calling the `spv.Verify` function to perform a series of checks.
4. Using `spv.GullibleHeadersClient` as a placeholder for actual block header validation.

The `spv.Verify` function typically checks:
- The internal consistency and validity of the BEEF structure.
- The syntactic validity of the transaction's input and output scripts.
- The correctness of the Merkle path against the transaction ID (i.e., the transaction is correctly placed in its purported Merkle tree).
- (Optionally) Fee verification if a `FeeVerifier` is provided.
- Confirmation of the Merkle root against a block header obtained via the `spv.Headers` client.

## Code Walkthrough

### Verifying the Transaction

```go
// BEEF data as a hex string (truncated for brevity)
const BEEFHex = "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000"

// Create transaction from BEEF hex
tx, err := transaction.NewTransactionFromBEEFHex(BEEFHex)
if err != nil {
    panic(err)
}

// Perform SPV verification
// This checks BEEF structure, script validity, Merkle path,
// and (conceptually) block header confirmation.
// GullibleHeadersClient trusts any header. No FeeVerifier is provided.
verified, _ := spv.Verify(tx, &spv.GullibleHeadersClient{}, nil)
println(verified)
```

This section shows loading a transaction from BEEF hex. The `spv.Verify` function is then called. It uses the `MerklePath` embedded within the `tx` object (which comes from the BEEF data) and the provided `spv.Headers` client.

Because `spv.GullibleHeadersClient` is used, the block header check will always pass. Thus, `verified` will be true if the BEEF structure is valid, the transaction scripts are syntactically correct, and the Merkle path correctly proves the transaction's inclusion in *some* Merkle tree. It does not, with this client, confirm that the transaction is in a block on the actual main chain.

## Running the Example

To run this example:

```bash
go run verify_transaction.go
```

The output will be `true` if the transaction passes all checks relative to the `GullibleHeadersClient` (i.e., scripts are valid, Merkle proof is internally consistent).

**Note**:
- The example uses a hardcoded BEEF hex string.
- `spv.GullibleHeadersClient` is used for simplicity. For true SPV, a `headers_client.Client` connected to a real headers service should be used.
- A `FeeVerifier` (the third argument to `spv.Verify`) can be provided to check if the transaction pays adequate fees, but it's `nil` in this example.

## Integration Steps

To integrate transaction verification into your application:
1. Obtain the transaction data, preferably in BEEF format (hex or binary) to include the Merkle proof.
2. Create a `transaction.Transaction` object (e.g., using `transaction.NewTransactionFromBEEFHex()`).
3. Initialize a proper `spv.Headers` client, like `headers_client.Client`, configured for your network and a trusted headers source.
4. (Optional) Create and configure a `FeeVerifier` if you need to check transaction fees.
5. Call `spv.Verify(yourTransaction, yourHeadersClient, yourFeeVerifier)`.
   - A `true` result indicates the transaction is valid, confirmed, and (if applicable) meets fee requirements according to your provided clients.
   - A `false` result or an error indicates a failure in one of the verification steps.

## Additional Resources

For more information, see:
- [Package Documentation - SPV](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/spv)
- [Package Documentation - Transaction](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/transaction)
- [Package Documentation - Headers Client](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/transaction/chaintracker/headers_client)
- [Verify BEEF Example](../verify_beef/)
- [Validate SPV Example](../validate_spv/)
