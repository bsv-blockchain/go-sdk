# Validate SPV (BEEF) Example

This example demonstrates how to use the `transaction` and `headers_client` packages to validate a transaction's Merkle proof (contained within a BEEF data structure) against a block header. This is a core part of Simplified Payment Verification (SPV).

## Overview

The `validate_spv` example showcases:
1. Decoding a Base64 encoded BEEF (Bitcoin Extended Envelope Format) string.
2. Creating a `transaction.Transaction` object from the BEEF data.
3. Extracting the Merkle path and block height from the transaction.
4. Computing the Merkle root from the transaction's Merkle path and its ID.
5. Using a `headers_client.Client` (conceptually) to check if the computed Merkle root is valid for the given block height.

## Code Walkthrough

### Processing BEEF and Validating Merkle Proof

```go
// Base64 encoded BEEF data (truncated for brevity)
beefString := "AQC+7wH+kQYNAAcCVAIKXThHm90iVbs15AIfFQEYl5xesbHCXMkYy9SqoR1vNVUAAZFHZkdkWeD0mUHP/kCkyoVXXC15rMA8tMP/F6738iwBKwCAMYdbLFfXFlvz5q0XXwDZnaj73hZrOJxESFgs2kfYPQEUAMDiGktI+c5Wzl35XNEk7phXeSfEVmAhtulujP3id36UAQsAkekX7uvGTir5i9nHAbRcFhvi88/9WdjHwIOtAc76PdsBBACO8lHRXtRZK+tuXsbAPfOuoK/bG7uFPgcrbV7cl/ckYQEDAAjyH0EYt9rEd4TrWj6/dQPX9pBJnulm6TDNUSwMRJGBAQAA2IGpOsjMdZ6u69g4z8Q0X/Hb58clIDz8y4Mh7gjQHrsJAQAAAAGiNgu1l9P6UBCiEHYC6f6lMy+Nfh9pQGklO/1zFv04AwIAAABqRzBEAiBt6+lIB2/OSNzOrB8QADEHwTvl/O9Pd9TMCLmV8K2mhwIgC6fGUaZSC17haVpGJEcc0heGxmu6zm9tOHiRTyytPVtBIQLGxNeyMZsFPL4iTn7yT4S0XQPnoGKOJTtPv4+5ktq77v////8DAQAAAAAAAAB/IQOb9SFSZlaZ4kwQGL9bSOV13jFvhElip52zK5O34yi/cawSYmVuY2htYXJrVG9rZW5fOTk5RzBFAiEA0KG8TGPpoWTh3eNZu8WhUH/eL8D/TA8GC9Tfs5TIGDMCIBIZ4Vxoj5WY6KM/bH1a8RcbOWxumYZsnMU/RthviWFDbcgAAAAAAAAAGXapFHpPGSoGhmZHz0NwEsNKYTuHopeTiKw1SQAAAAAAABl2qRQhSuHh+ETVgSwVNYwwQxE1HRMh6YisAAAAAAEAAQAAAAEKXThHm90iVbs15AIfFQEYl5xesbHCXMkYy9SqoR1vNQIAAABqRzBEAiANrOhLuR2njxZKOeUHiILC/1UUpj93aWYG1uGtMwCzBQIgP849avSAGRtTOC7hcrxKzdzgsUfFne6T6uVNehQCrudBIQOP+/6gVhpmL5mHjrpusZBqw80k46oEjQ5orkbu23kcIP////8DAQAAAAAAAAB9IQOb9SFSZlaZ4kwQGL9bSOV13jFvhElip52zK5O34yi/cawQYmVuY2htYXJrVG9rZW5fMEcwRQIhAISNx6VL+LwnZymxuS7g2bOhVO+sb2lOs7wpDJFVkQCzAiArQr3G2TZcKnyg/47OSlG7XW+h6CTkl+FF4FlO3khrdG3IAAAAAAAAABl2qRTMh3rEbc9boUbdBSu8EvwE9FpcFYisa0gAAAAAAAAZdqkUDavGkHIDei8GA14PE9pui/adYxOIrAAAAAAAAQAAAAG+I3gM0VUiDYkYn6HnijD5X1nRA6TP4M9PnS6DIiv8+gIAAABqRzBEAiBqB4v3J0nlRjJAEXf5/Apfk4Qpq5oQZBZR/dWlKde45wIgOsk3ILukmghtJ3kbGGjBkRWGzU7J+0e7RghLBLe4H79BIQJvD8752by3nrkpNKpf5Im+dmD52AxHz06mneVGeVmHJ/////8DAQAAAAAAAAB8IQOb9SFSZlaZ4kwQGL9bSOV13jFvhElip52zK5O34yi/cawQYmVuY2htYXJrVG9rZW5fMUYwRAIgYCfx4TRmBa6ZaSlwG+qfeyjwas09Ehn5+kBlMIpbjsECIDohOgL9ssMXo043vJx2RA4RwUSzic+oyrNDsvH3+GlhbcgAAAAAAAAAGXapFCR85IaVea4Lp20fQxq6wDUa+4KbiKyhRwAAAAAAABl2qRRtQlA5LLnIQE6FKAwoXWqwx1IPxYisAAAAAAABAAAAATQCyNdYMv3gisTSig8QHFSAtZogx3gJAFeCLf+T6ftKAgAAAGpHMEQCIBxDKsYb3o9/mkjqU3wkApD58TakUxcjVxrWBwb+KZCNAiA/N5mst9Y5R9z0nciIQxj6mjSDX8a48tt71WMWle2XG0EhA1bL/xbl8RY7bvQKLiLKeiTLkEogzFcLGIAKB0CJTDIt/////wMBAAAAAAAAAH0hA5v1IVJmVpniTBAYv1tI5XXeMW+ESWKnnbMrk7fjKL9xrBBiZW5jaG1hcmtUb2tlbl8yRzBFAiEAprd99c9CM86bHYxii818vfyaa+pbqQke8PMDdmWWbhgCIG095qrWtjvzGj999PrjifFtV0mNepQ82IWkgRUSYl4dbcgAAAAAAAAAGXapFFChFep+CB3Qdpssh55ZAh7Z1B9AiKzXRgAAAAAAABl2qRQI3se+hqgRme2BD/l9/VGT8fzze4isAAAAAAABAAAAATYrcW2trOWKTN66CahA2iVdmw9EoD3NRfSxicuqf2VZAgAAAGpHMEQCIGLzQtoohOruohH2N8f85EY4r07C8ef4sA1zpzhrgp8MAiB7EPTjjK6bA5u6pcEZzrzvCaEjip9djuaHNkh62Ov3lEEhA4hF47lxu8l7pDcyBLhnBTDrJg2sN73GTRqmBwvXH7hu/////wMBAAAAAAAAAH0hA5v1IVJmVpniTBAYv1tI5XXeMW+ESWKnnbMrk7fjKL9xrBBiZW5jaG1hcmtUb2tlbl8zRzBFAiEAgHsST5TSjs4SaxQo/ayAT/i9H+/K6kGqSOgiXwJ7MEkCIB/I+awNxfAbjtCXJfu8PkK3Gm17v14tUj2U4N7+kOYPbcgAAAAAAAAAGXapFESF1LKTxPR0Lp/YSAhBv1cqaB5jiKwNRgAAAAAAABl2qRRMDm8dYnq71SvC2ZW85T4wiK1d44isAAAAAAABAAAAAZlmx40ThobDzbDV92I652mrG99hHvc/z2XDZCxaFSdOAgAAAGpHMEQCIGd6FcM+jWQOI37EiQQX1vLsnNBIRpWm76gHZfmZsY0+AiAQCdssIwaME5Rm5dyhM8N8G4OGJ6U8Ec2jIdVO1fQyIkEhAj6oxrKo6ObL1GrOuwvOEpqICEgVndhRAWh1qL5awn29/////wMBAAAAAAAAAH0hA5v1IVJmVpniTBAYv1tI5XXeMW+ESWKnnbMrk7fjKL9xrBBiZW5jaG1hcmtUb2tlbl80RzBFAiEAtnby9Is30Kad+SeRR44T9vl/XgLKB83wo8g5utYnFQICIBdeBto6oVxzJRuWOBs0Dqeb0EnDLJWw/Kg0fA0wjXFUbcgAAAAAAAAAGXapFPif6YFPsfQSAsYD0phVFDdWnITziKxDRQAAAAAAABl2qRSzMU4yDCTmCoXgpH461go08jpAwYisAAAAAAABAAAAAfFifKQeabVQuUt9F1rQiVz/iZrNQ7N6Vrsqs0WrDolhAgAAAGpHMEQCIC/4j1TMcnWc4FIy65w9KoM1h+LYwwSL0g4Eg/rwOdovAiBjSYcebQ/MGhbX2/iVs4XrkPodBN/UvUTQp9IQP93BsEEhAuvPbcwwKILhK6OpY6K+XqmqmwS0hv1cH7WY8IKnWkTk/////wMBAAAAAAAAAHwhA5v1IVJmVpniTBAYv1tI5XXeMW+ESWKnnbMrk7fjKL9xrBBiZW5jaG1hcmtUb2tlbl81RjBEAiAfXkdtFBi9ugyeDKCKkeorFXRAAVOS/dGEp0DInrwQCgIgdkyqe70lCHIalzS4nFugA1EUutCh7O2aUijN6tHxGVBtyAAAAAAAAAAZdqkUTHmgM3RpBYmbWxqYgeOA8zdsyfuIrHlEAAAAAAAAGXapFOLz0OAGrxiGzBPRvLjAoDp7p/VUiKwAAAAAAAEAAAABODRQbkr3Udw6DXPpvdBncJreUkiGCWf7PrcoVL5gEdwCAAAAa0gwRQIhAIq/LOGvvMPEiVJlsJZqxp4idfs1pzj5hztUFs07tozBAiAskG+XcdLWho+Bo01qOvTNfeBwlpKG23CXxeDzoAm2OEEhAvaoHEQtzZA8eAinWr3pIXJou3BBetU4wY+1l7TFU8NU/////wMBAAAAAAAAAH0hA5v1IVJmVpniTBAYv1tI5XXeMW+ESWKnnbMrk7fjKL9xrBBiZW5jaG1hcmtUb2tlbl82RjBEAiA0yjzEkWPk1bwk9BxepGMe/UrnwkP5BMkOHbbmpV6PDgIga7AxusovxtZNpa1yLOLgcTdxjl5YCS5ez1TlL83WZKttyAAAAAAAAAAZdqkUcHY6VT1hWoFE+giJoOH5PR2NqLCIrK9DAAAAAAAAGXapFFqhL5vgEh7uVOczHY+ZX+Td7XL1iKwAAAAAAAEAAAABXCLo00qVp2GgaFuLWpmghF6fA9h9VxanNR0Ik521zZICAAAAakcwRAIgUQHyvcQAmMveGicAcaW/3VpvvvyKOKi0oa2soKb/VecCIA7FwKV8tl38aqIuaFa7TGK4mHp7n6MstgHJS1ebpn2DQSEDyL5rIX/FWTmFHigjn7v3MfmX4CatNEqp1Lc5GB/pZ0P/////AwEAAAAAAAAAfCEDm/UhUmZWmeJMEBi/W0jldd4xb4RJYqedsyuTt+Mov3GsEGJlbmNobWFya1Rva2VuXzdGMEQCIAJoCOlFP3XKH8PHuw974e+spc6mse2parfbVsUZtnkyAiB9H6Xn1VJU0hQiVpR/k6BheBKApu0kZAUkcGM6fIiNH23IAAAAAAAAABl2qRQou28gesj0t/bBxZFOFDphZVhrJIis5UIAAAAAAAAZdqkUGXy953q7y5hcpgqFwpiLKsMsVBqIrAAAAAAA"
BEEF, err := base64.StdEncoding.DecodeString(beefString)
// ... handle error ...

// Initialize headers client (replace with actual URL and API key)
client := headers_client.Client{
    Url:    "headers_url",
    ApiKey: "your_api_key_here",
}

// Create transaction from BEEF
tx, err := transaction.NewTransactionFromBEEF(BEEF)
// ... handle error ...

// Compute Merkle root
root, err := tx.MerklePath.ComputeRoot(tx.TxID())
// ... handle error ...

// Validate Merkle root against block height
valid, err := client.IsValidRootForHeight(root, tx.MerklePath.BlockHeight)
// ... handle error ...
fmt.Println("Is valid root for height:", valid)
```

This section shows the decoding of BEEF, creation of a transaction object, computation of the Merkle root, and then validation of this root against the block height recorded in the Merkle path using a `headers_client.Client`.

## Running the Example

To run this example:

```bash
go run validate_spv.go
```

The output will indicate whether the Merkle root is considered valid for the block height. Since the `headers_client.Client` is not configured with a real endpoint, this will likely result in an error or a `false` validation unless the client is modified to mock a successful response.

**Note**:
- The example uses a hardcoded, very long Base64 string for BEEF data.
- The `headers_client.Client` requires a valid URL for a headers service (like a TAAL MAPI or similar) and potentially an API key to function correctly in a real scenario. The example uses placeholder values.
- True SPV validation involves fetching the actual block header for `tx.MerklePath.BlockHeight` from a trusted source (or multiple sources) and confirming that `root` matches the `MerkleRoot` field in that header. The `IsValidRootForHeight` method abstracts this check.

## Integration Steps

To integrate SPV validation into your application:
1. Obtain BEEF data for the transaction you want to validate.
2. Decode the BEEF and create a `transaction.Transaction` object using `transaction.NewTransactionFromBEEF()`.
3. Extract the `MerklePath` from the transaction.
4. Compute the Merkle root using `merklePath.ComputeRoot(tx.TxID())`.
5. Configure a `headers_client.Client` with a reliable headers service endpoint.
6. Call `client.IsValidRootForHeight(computedRoot, merklePath.BlockHeight)` to verify the proof. This method internally fetches the necessary block header and compares the Merkle roots.
7. Optionally, for higher security, you can fetch the header from multiple sources or verify a chain of headers back to a known checkpoint.

## Additional Resources

For more information, see:
- [Package Documentation - Transaction](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/transaction)
- [Package Documentation - Headers Client](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/transaction/chaintracker/headers_client)
- [Verify BUMP/BEEF Example](../verify_beef/)
