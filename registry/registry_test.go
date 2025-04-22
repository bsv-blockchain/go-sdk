package registry

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockLookupResolver is a mock implementation that satisfies both the LookupResolver and Facilitator interfaces
type MockLookupResolver struct {
	QueryFunc  func(ctx context.Context, question *lookup.LookupQuestion, timeout interface{}) (*lookup.LookupAnswer, error)
	LookupFunc func(ctx context.Context, host string, question *lookup.LookupQuestion, timeout time.Duration) (*lookup.LookupAnswer, error)
}

// Query satisfies part of the functionality of LookupResolver
func (m *MockLookupResolver) Query(ctx context.Context, question *lookup.LookupQuestion, timeout interface{}) (*lookup.LookupAnswer, error) {
	if m.QueryFunc != nil {
		return m.QueryFunc(ctx, question, timeout)
	}
	return nil, nil
}

// Lookup satisfies the lookup.Facilitator interface
func (m *MockLookupResolver) Lookup(ctx context.Context, host string, question *lookup.LookupQuestion, timeout time.Duration) (*lookup.LookupAnswer, error) {
	if m.LookupFunc != nil {
		return m.LookupFunc(ctx, host, question, timeout)
	}
	// By default, just call QueryFunc if LookupFunc isn't set
	if m.QueryFunc != nil {
		return m.QueryFunc(ctx, question, timeout)
	}
	return nil, nil
}

func TestRegistryClient_RegisterDefinition(t *testing.T) {
	// Skip for now - this test needs more work to mock the PushDrop template
	// TODO: Fix this test by properly mocking the CreateSignature method in the MockWallet
	t.Skip("This test is not yet implemented because the MockWallet needs to implement CreateSignature")

	ctx := context.Background()
	mockRegistry := NewMockRegistry(t)

	// Create a test public key
	pubKeyBytes := []byte{
		0x02, // Compressed key prefix (even y)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	testPubKey, err := ec.PublicKeyFromBytes(pubKeyBytes)
	require.NoError(t, err)

	// Setup mock GetPublicKey response
	mockRegistry.GetPublicKeyResult = &wallet.GetPublicKeyResult{
		PublicKey: testPubKey,
	}

	// Setup mock CreateAction response
	mockRegistry.CreateActionResultToReturn = &wallet.CreateActionResult{
		Tx: []byte("mock_transaction_beef"),
	}

	// Create registry client with mock wallet
	client := NewRegistryClient(mockRegistry, "test_originator")

	// Mock the lookup factory to return our mock resolver
	client.lookupFactory = func() *lookup.LookupResolver {
		return &lookup.LookupResolver{}
	}

	// Create test basket definition
	basketDef := &BasketDefinitionData{
		DefinitionType:   DefinitionTypeBasket,
		BasketID:         "test_basket_id",
		Name:             "Test Basket",
		IconURL:          "https://example.com/icon.png",
		Description:      "Test basket description",
		DocumentationURL: "https://example.com/docs",
	}

	// Test RegisterDefinition
	result, err := client.RegisterDefinition(ctx, basketDef)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestRegistryClient_ResolveBasket(t *testing.T) {
	// Skip for now - this test needs more work to properly mock the lookup resolver
	// TODO: Fix this test to properly mock the lookup resolver without making network calls
	t.Skip("This test is not yet implemented because it needs a more sophisticated mock")

	ctx := context.Background()
	mockRegistry := NewMockRegistry(t)

	// Create a mock lookup resolver
	mockResolver := &MockLookupResolver{}

	// Setup mock lookup result
	mockResolver.QueryFunc = func(ctx context.Context, question *lookup.LookupQuestion, timeout interface{}) (*lookup.LookupAnswer, error) {
		// Verify the lookup question
		assert.Equal(t, "ls_basketmap", question.Service)

		// Parse the query to verify it matches what we expect
		var query BasketQuery
		err := json.Unmarshal(question.Query, &query)
		assert.NoError(t, err)
		assert.Equal(t, *query.BasketID, "test_basket_id")

		// Create a mock transaction with locking script
		tx := transaction.NewTransaction()
		scriptStr := "OP_FALSE OP_RETURN 74657374 626173686b65745f6964 54657374204261736b6574 68747470733a2f2f6578616d706c652e636f6d2f69636f6e2e706e67 54657374206261736b6574206465736372697074696f6e 68747470733a2f2f6578616d706c652e636f6d2f646f6373 030000000000000000000000000000000000000000000000000000000000000001"
		lockingScript, _ := script.NewFromASM(scriptStr)
		tx.AddOutput(&transaction.TransactionOutput{
			Satoshis:      1000,
			LockingScript: lockingScript,
		})

		beef, _ := tx.AtomicBEEF(false)

		// Return mock lookup answer
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

	// Create registry client with mock wallet
	client := NewRegistryClient(mockRegistry, "test_originator")

	// Create test query
	basketID := "test_basket_id"
	query := BasketQuery{
		BasketID: &basketID,
	}

	// Test ResolveBasket
	results, err := client.ResolveBasket(ctx, query)
	require.NoError(t, err)
	require.Len(t, results, 0) // Expect 0 because we're returning empty slice
}

func TestRegistryClient_ListOwnRegistryEntries(t *testing.T) {
	// We can now implement this test using our MockRegistry
	// TODO: Implement this test using the MockRegistry.ListOutputsResultToReturn
	ctx := context.Background()
	mockRegistry := NewMockRegistry(t)

	// Setup mock ListOutputs response
	// Create a mock transaction containing our locking script
	mockTx := transaction.NewTransaction()

	// Create a PushDrop locking script
	// The script needs to have the following format:
	// <public_key> OP_CHECKSIG <field1> <field2> <field3> <field4> <field5> <field6> OP_2DROP OP_2DROP OP_2DROP
	// Let's use a utility function to create a realistic script with all the proper drops

	// Create a mock public key and fields
	publicKeyBytes := []byte{
		0x02, // Compressed key prefix (even y)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}

	// Create script parts
	// Note: pushdrop.Decode reads these in reverse order and preserves the last 6 fields before a DROP
	scriptChunks := []*script.ScriptChunk{
		// The public key
		{
			Op:   byte(len(publicKeyBytes)),
			Data: publicKeyBytes,
		},
		// OP_CHECKSIG
		{
			Op: script.OpCHECKSIG,
		},
		// Field 1: basket ID
		{
			Op:   byte(len("test basket_id")),
			Data: []byte("test basket_id"),
		},
		// Field 2: name
		{
			Op:   byte(len("Test Basket")),
			Data: []byte("Test Basket"),
		},
		// Field 3: icon URL
		{
			Op:   byte(len("http://example.com/icon.png")),
			Data: []byte("http://example.com/icon.png"),
		},
		// Field 4: description
		{
			Op:   byte(len("Test basket description")),
			Data: []byte("Test basket description"),
		},
		// Field 5: documentation URL
		{
			Op:   byte(len("http://example.com/docs")),
			Data: []byte("http://example.com/docs"),
		},
		// Field 6: registry operator (public key)
		{
			Op:   byte(len(publicKeyBytes)),
			Data: publicKeyBytes,
		},
		// OP_2DROP (drops fields 5-6)
		{
			Op: script.Op2DROP,
		},
		// OP_2DROP (drops fields 3-4)
		{
			Op: script.Op2DROP,
		},
		// OP_2DROP (drops fields 1-2)
		{
			Op: script.Op2DROP,
		},
	}

	// Create the script from chunks
	lockingScript, err := script.NewScriptFromScriptOps(scriptChunks)
	require.NoError(t, err)

	// Add the output to the transaction
	mockTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1000,
		LockingScript: lockingScript,
	})

	// Generate BEEF data
	beef, err := mockTx.AtomicBEEF(false)
	require.NoError(t, err)

	// Convert the locking script to a hex string for the mock output
	lockingScriptStr := lockingScript.String()

	// Test the parseLockingScript function directly to diagnose issues
	parsedData, err := parseLockingScript(DefinitionTypeBasket, lockingScript)
	if err != nil {
		t.Logf("Failed to parse locking script: %v", err)
		decoded := pushdrop.Decode(lockingScript)
		if decoded == nil {
			t.Logf("pushdrop.Decode returned nil")
		} else {
			t.Logf("Decoded fields count: %d", len(decoded.Fields))
			for i, field := range decoded.Fields {
				t.Logf("Field %d: %s", i, string(field))
			}
		}

		// Print the script in a readable format
		chunks, _ := lockingScript.Chunks()
		t.Logf("Script chunks: %d", len(chunks))
		for i, chunk := range chunks {
			if len(chunk.Data) > 0 {
				t.Logf("Chunk %d: op=%d data=%s", i, chunk.Op, string(chunk.Data))
			} else {
				t.Logf("Chunk %d: op=%d", i, chunk.Op)
			}
		}
	} else {
		basketData, ok := parsedData.(*BasketDefinitionData)
		require.True(t, ok, "Failed to cast to BasketDefinitionData")
		t.Logf("Successfully parsed script: basketID=%s, name=%s",
			basketData.BasketID, basketData.Name)
	}

	mockRegistry.ListOutputsResultToReturn = &wallet.ListOutputsResult{
		TotalOutputs: 1,
		Outputs: []wallet.Output{
			{
				Satoshis:      1000,
				LockingScript: lockingScriptStr,
				Spendable:     true,
				Outpoint:      "abcd1234.0", // Format: txid.index
				Tags:          []string{"registry", "basket"},
			},
		},
		BEEF: beef,
	}

	// Create registry client with mock wallet
	client := NewRegistryClient(mockRegistry, "test_originator")

	// Create test query
	definitionType := DefinitionTypeBasket

	// Test ListOwnRegistryEntries
	results, err := client.ListOwnRegistryEntries(ctx, definitionType)
	require.NoError(t, err)
	require.NotNil(t, results)

	// If results is empty, add debug logging to see what's happening
	if len(results) == 0 {
		t.Logf("Results is empty, adding debug info")
		t.Logf("BEEF length: %d", len(beef))
		t.Logf("LockingScript: %s", lockingScriptStr)
		// Try to parse the locking script directly
		decoded := pushdrop.Decode(lockingScript)
		if decoded == nil {
			t.Logf("Failed to decode script with pushdrop.Decode")
		} else {
			t.Logf("Decoded fields count: %d", len(decoded.Fields))
			for i, field := range decoded.Fields {
				t.Logf("Field %d: %s", i, string(field))
			}
		}
	}

	require.Len(t, results, 1)
	require.Equal(t, "test basket_id", results[0].DefinitionData.(*BasketDefinitionData).BasketID)
}

func TestRegistryClient_RevokeOwnRegistryEntry(t *testing.T) {
	// Skip for now - this test needs more work to mock the GetPublicKey, CreateAction, and SignAction methods
	// TODO: Fix this test by properly mocking the GetPublicKey, CreateAction, and SignAction methods in the MockWallet
	t.Skip("This test is not yet implemented because the MockWallet needs to implement GetPublicKey, CreateAction, and SignAction")

	ctx := context.Background()
	mockRegistry := NewMockRegistry(t)

	// Create registry client with mock wallet
	client := NewRegistryClient(mockRegistry, "test_originator")

	// TODO: Setup mock GetPublicKey, CreateAction, and SignAction responses

	// Create test registry record
	record := &RegistryRecord{
		DefinitionData: &BasketDefinitionData{
			DefinitionType:   DefinitionTypeBasket,
			BasketID:         "test_basket_id",
			Name:             "Test Basket",
			IconURL:          "https://example.com/icon.png",
			Description:      "Test basket description",
			DocumentationURL: "https://example.com/docs",
			RegistryOperator: "030000000000000000000000000000000000000000000000000000000000000001",
		},
		TokenData: TokenData{
			TxID:          "abcd1234",
			OutputIndex:   0,
			Satoshis:      1000,
			LockingScript: "OP_FALSE OP_RETURN 74657374 626173686b65745f6964 54657374204261736b6574 68747470733a2f2f6578616d706c652e636f6d2f69636f6e2e706e67 54657374206261736b6574206465736372697074696f6e 68747470733a2f2f6578616d706c652e636f6d2f646f6373 030000000000000000000000000000000000000000000000000000000000000001",
			BEEF:          []byte("mock_transaction_beef"),
		},
	}

	// Test RevokeOwnRegistryEntry
	result, err := client.RevokeOwnRegistryEntry(ctx, record)
	require.Error(t, err) // Expect error because we're not properly mocking GetPublicKey, CreateAction, and SignAction
	require.Nil(t, result)
}
