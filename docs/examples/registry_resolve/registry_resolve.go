package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/registry"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// This example demonstrates how to use the RegistryClient to resolve a basket definition
// In a real application, you would connect to the network to resolve entries
// Here we use mock responses for demonstration purposes.
func main() {
	// Create a test instance
	test := &testing.T{}

	// Create a mock wallet
	mockWallet := registry.NewMockRegistry(test)

	// Create a registry client with the mock wallet
	client := registry.NewRegistryClient(mockWallet, "example-registry-app")

	// Create a mock lookup resolver
	// In a real application, you would use the registry client's default resolver
	// which is set up during initialization
	_ = &MockLookupResolver{} // Just for example purposes

	// Create a context
	ctx := context.Background()

	// Create a query for a specific basket
	basketID := "example-basket-id"
	query := registry.BasketQuery{
		BasketID: &basketID,
	}

	// Resolve the basket
	fmt.Println("Resolving basket definition...")
	results, err := client.ResolveBasket(ctx, query)
	if err != nil {
		log.Fatalf("Failed to resolve basket: %v", err)
	}

	// Print the results
	fmt.Printf("Found %d basket definitions\n", len(results))
	for i, basket := range results {
		fmt.Printf("Basket %d:\n", i+1)
		fmt.Printf("  Basket ID: %s\n", basket.BasketID)
		fmt.Printf("  Name: %s\n", basket.Name)
		fmt.Printf("  Description: %s\n", basket.Description)
		fmt.Printf("  Icon URL: %s\n", basket.IconURL)
		fmt.Printf("  Documentation URL: %s\n", basket.DocumentationURL)
		fmt.Printf("  Registry Operator: %s\n", basket.RegistryOperator)
	}
}

// MockLookupResolver is a mock implementation of the lookup.Facilitator interface
type MockLookupResolver struct{}

// Query implements the lookup.LookupResolver Query method
func (m *MockLookupResolver) Query(ctx context.Context, question *lookup.LookupQuestion, timeout interface{}) (*lookup.LookupAnswer, error) {
	// Check if this is a basket query
	if question.Service != "ls_basketmap" {
		return nil, fmt.Errorf("unsupported service: %s", question.Service)
	}

	// Parse the query to verify the basket ID
	var query registry.BasketQuery
	if err := json.Unmarshal(question.Query, &query); err != nil {
		return nil, err
	}

	// Create a mock transaction with a locking script
	tx := transaction.NewTransaction()

	// Create a mock output with PushDrop fields that match our basket
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1000,
		LockingScript: createMockBasketScript(),
	})

	// Generate BEEF data
	beef, _ := tx.AtomicBEEF(false)

	// Return a mock lookup answer
	return &lookup.LookupAnswer{
		Type: lookup.AnswerTypeOutputList,
		Outputs: []*lookup.OutputListItem{
			{
				Beef:        beef,
				OutputIndex: 0,
			},
		},
	}, nil
}

// Lookup delegates to Query and is required for the interface
func (m *MockLookupResolver) Lookup(ctx context.Context, host string, question *lookup.LookupQuestion, timeout time.Duration) (*lookup.LookupAnswer, error) {
	return m.Query(ctx, question, timeout)
}

// createMockBasketScript creates a mock locking script for a basket definition
// This is a simplified version of what would actually be on-chain
func createMockBasketScript() *script.Script {
	// In a real implementation, this would create a proper PushDrop script
	// with the correct structure for a basket definition
	scriptHex := "76a914000000000000000000000000000000000000000088ac0e6578616d706c652d6261736b65740e4578616d706c65204261736b65741a68747470733a2f2f6578616d706c652e636f6d2f69636f6e2e706e6732416e206578616d706c65206261736b6574206465736372697074696f6e20666f722074686520425356207265676973747279" +
		"1d68747470733a2f2f6578616d706c652e636f6d2f646f63732f00000000006e6e6e"

	// Create script from hex string
	s, err := script.NewFromHex(scriptHex)
	if err != nil {
		log.Fatalf("Failed to create script from hex: %v", err)
	}
	return s
}
