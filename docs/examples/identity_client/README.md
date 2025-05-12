# Identity Client Example

This example demonstrates how to use the `IdentityClient` from the BSV Go SDK to manage and resolve identity certificates.

## Features Demonstrated

1. **Creating an Identity Client**
   - Initialize with default or custom settings

2. **Publicly Revealing Attributes**
   - Selectively reveal identity attributes on the blockchain
   - Using both standard and simplified TypeScript-compatible APIs

3. **Identity Resolution**
   - Resolving identities by identity key
   - Resolving identities by specific attributes

4. **Direct Identity Certificate Parsing**
   - Converting a certificate directly to a displayable identity

## Running the Example

```bash
cd docs/examples/identity_client
go run main.go
```

## Notes

- This example demonstrates the API usage but won't successfully broadcast transactions unless you provide real certificate data.
- In a real application, you would obtain certificates through `wallet.acquireCertificate()` or another mechanism.
- The example uses mock data to show the structure and flow of using the Identity Client.

## Learn More

For more detailed information about identity management and verification in the SDK, refer to:
- [Identity Client Documentation](../../identity/README.md)
- [Identity Concepts](../../concepts/IDENTITY.md) 