# Registry Register Example

This example demonstrates how to use the `registry` package, specifically the `RegistryClient`, to register a new basket definition on the BSV blockchain.

## Overview

The `registry_register` example showcases:
1. Creating a `RegistryClient` instance.
2. Defining a `BasketDefinitionData` structure with metadata for a new basket.
3. Calling `client.RegisterDefinition` to create and (conceptually) broadcast the registration transaction.
4. Handling the result of the registration.

## Code Walkthrough

### Setting Up and Registering

```go
// Create a mock wallet (for example purposes only)
mockWallet := registry.NewMockRegistry(test)

// Create a registry client with the mock wallet
client := registry.NewRegistryClient(mockWallet, "example-registry-app")

// Create a new basket definition
basketDef := &registry.BasketDefinitionData{
    DefinitionType:   registry.DefinitionTypeBasket,
    BasketID:         "example-basket-id",
    Name:             "Example Basket",
    // ... other fields ...
}

// Register the definition on-chain
result, err := client.RegisterDefinition(ctx, basketDef)
// ... handle result and error ...
```

This section shows the initialization of a `RegistryClient` (using a mock wallet for this example) and the creation of a `BasketDefinitionData` object. The `RegisterDefinition` method is then called to process the registration.

## Running the Example

To run this example:

```bash
go run registry_register.go
```

The output will indicate whether the registration was successful (based on the mock wallet's behavior) and print some details of the basket definition.

**Note**: This example uses a `MockRegistry` which simulates wallet interactions without actual on-chain transactions or network communication. In a real-world application:
- You would need a fully implemented `wallet.Interface` that can sign and broadcast transactions.
- The `CreateActionResultToReturn` on the mock is used here to simulate a successful transaction.
- Proper error handling and response parsing from the actual wallet/network would be required.

## Integration Steps

To integrate registry functionality into your application:
1. Implement or utilize a `wallet.Interface` that can interact with the BSV blockchain.
2. Initialize a `registry.NewRegistryClient` with your wallet instance and an application identifier.
3. Populate a `BasketDefinitionData` (or other relevant definition type) structure with your metadata.
4. Call `client.RegisterDefinition()` to create the registration transaction.
5. Handle the transaction result, including storing the transaction ID and any other relevant information.

## Additional Resources

For more information, see:
- [Package Documentation](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/registry)
- [Registry Resolve Example](../registry_resolve/)
