package main

import (
	"context"
	"fmt"
	"log"
	"testing"

	"github.com/bsv-blockchain/go-sdk/registry"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// This example shows how to use the RegistryClient to register a basket definition
// In a real application, you would use a wallet implementation to sign and broadcast
// transactions. Here we use a mock wallet for demonstration purposes.
func main() {
	// Create a test instance
	test := &testing.T{}

	// Create a mock wallet (for example purposes only)
	mockWallet := registry.NewMockRegistry(test)

	// Set up mock response
	mockWallet.CreateActionResultToReturn = &wallet.CreateActionResult{
		Tx: []byte("mock_transaction_beef"),
	}

	// Create a context
	ctx := context.Background()

	// Create a registry client with the mock wallet
	client := registry.NewRegistryClient(mockWallet, "example-registry-app")

	// Create a new basket definition
	basketDef := &registry.BasketDefinitionData{
		DefinitionType:   registry.DefinitionTypeBasket,
		BasketID:         "example-basket-id",
		Name:             "Example Basket",
		IconURL:          "https://example.com/icon.png",
		Description:      "An example basket definition for the BSV registry",
		DocumentationURL: "https://example.com/docs",
	}

	// Register the definition on-chain
	fmt.Println("Registering basket definition...") //nolint:forbidigo // example program output
	result, err := client.RegisterDefinition(ctx, basketDef)
	if err != nil {
		log.Fatalf("Failed to register definition: %v", err)
	}

	// Print the result
	fmt.Printf("Successfully registered basket definition!\n") //nolint:forbidigo // example program output
	if result.Success != nil {
		fmt.Printf("Success: %+v\n", result.Success) //nolint:forbidigo // example program output
	} else if result.Failure != nil {
		fmt.Printf("Failure: %+v\n", result.Failure) //nolint:forbidigo // example program output
	}
	fmt.Printf("Basket ID: %s\n", basketDef.BasketID) //nolint:forbidigo // example program output
	fmt.Printf("Name: %s\n", basketDef.Name)          //nolint:forbidigo // example program output

	// NOTE: In a real application, you would:
	// 1. Create a proper wallet implementation
	// 2. Handle the broadcast response appropriately
	// 3. Store the transaction information for future reference
}
