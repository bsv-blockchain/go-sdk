# Registry Resolve Example

This example demonstrates how to use the `registry` package, specifically the `RegistryClient`, to resolve (look up) basket definitions from the BSV blockchain.

## Overview

The `registry_resolve` example showcases:
1. Creating a `RegistryClient` instance.
2. Defining a `BasketQuery` to specify the basket to look up (by ID in this case).
3. Calling `client.ResolveBasket` to query the network (simulated here) for matching basket definitions.
4. Processing and displaying the resolved basket information.
5. Includes a `MockLookupResolver` to simulate network responses for the lookup.

## Code Walkthrough

### Setting Up and Resolving

```go
// Create a mock wallet and registry client
mockWallet := registry.NewMockRegistry(test)
client := registry.NewRegistryClient(mockWallet, "example-registry-app")

// Define a query for a specific basket ID
basketID := "example-basket-id"
query := registry.BasketQuery{
    BasketID: &basketID,
}

// Resolve the basket
results, err := client.ResolveBasket(ctx, query)
// ... handle results and error ...

for i, basket := range results {
    fmt.Printf("Basket %d:\n", i+1)
    fmt.Printf("  Basket ID: %s\n", basket.BasketID)
    // ... print other basket details ...
}
```

This section illustrates creating a `RegistryClient` and a `BasketQuery`. The `ResolveBasket` method is then used to find basket definitions matching the query. The example iterates through and prints the details of any found baskets.

### Mocking Network Responses

The example includes a `MockLookupResolver` that implements the `lookup.Facilitator` interface.
```go
type MockLookupResolver struct{}

func (m *MockLookupResolver) Query(ctx context.Context, question *lookup.LookupQuestion, timeout interface{}) (*lookup.LookupAnswer, error) {
    // ... logic to parse the question and return a mock answer ...
    // This involves creating a mock transaction with a PushDrop script
    // and BEEF data to simulate an on-chain entry.
    return &lookup.LookupAnswer{
        // ... mock answer data ...
    }, nil
}
```
This mock resolver intercepts lookup queries and returns predefined data, allowing the example to run without actual network interaction. It demonstrates how the client would interact with a lookup service to find on-chain registry entries.

## Running the Example

To run this example:

```bash
go run registry_resolve.go
```

The output will show the details of the mock basket definition returned by the `MockLookupResolver`.

**Note**: This example relies heavily on mocked components (`MockRegistry` and `MockLookupResolver`) to simulate blockchain and network interactions. In a real-world application:
- The `RegistryClient` would use a real `wallet.Interface` and its configured `lookup.Facilitator` (often the default one that queries actual lookup services).
- The `ResolveBasket` method would perform network requests to lookup services to find transactions containing the requested registry data.
- The data returned would be from actual on-chain PushDrop scripts.

## Integration Steps

To integrate basket resolution into your application:
1. Initialize a `registry.NewRegistryClient` with a real `wallet.Interface` and appropriate configuration (the default lookup resolver usually suffices).
2. Create a `registry.BasketQuery` object, specifying criteria like `BasketID`, `Name`, or `RegistryOperator`.
3. Call `client.ResolveBasket(ctx, query)` to find matching basket definitions.
4. Process the returned slice of `registry.BasketDefinitionData` objects. Each object represents a resolved basket definition.

## Additional Resources

For more information, see:
- [Package Documentation - Registry](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/registry)
- [Package Documentation - Overlay Lookup](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/overlay/lookup)
- [Registry Register Example](../registry_register/)
