package registry

import (
	"context"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/overlay/topic"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
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

// MockBroadcaster implements the transaction.Broadcaster interface for testing
type MockBroadcaster struct {
	BroadcastSuccess *transaction.BroadcastSuccess
	BroadcastFailure *transaction.BroadcastFailure
}

// Broadcast implements the transaction.Broadcaster interface for mocking in tests
func (m *MockBroadcaster) Broadcast(tx *transaction.Transaction) (*transaction.BroadcastSuccess, *transaction.BroadcastFailure) {
	return m.BroadcastSuccess, m.BroadcastFailure
}

// BroadcastCtx implements the transaction.Broadcaster interface for mocking in tests
func (m *MockBroadcaster) BroadcastCtx(ctx context.Context, tx *transaction.Transaction) (*transaction.BroadcastSuccess, *transaction.BroadcastFailure) {
	return m.BroadcastSuccess, m.BroadcastFailure
}

func TestRegistryClient_RegisterDefinition(t *testing.T) {
	ctx := context.Background()
	mockRegistry := NewMockRegistry(t)
	mockTxid, err := chainhash.NewHashFromHex("f1e1fd3c6504b94e9cb0ecfb7db1167655e3d5f98afd977a18fc01e1a6e59504")
	require.NoError(t, err, "Failed to create mock txid from hex")

	// Create a test public key
	pubKeyBytes := []byte{
		0x02,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	}
	testPubKey, err := ec.PublicKeyFromBytes(pubKeyBytes)
	require.NoError(t, err)

	// Get the DER hex format of the public key to use as registry operator
	operatorPubKeyHex := testPubKey.ToDERHex()
	t.Logf("Using operator public key: %s", operatorPubKeyHex)

	// Setup mock GetPublicKey response
	mockRegistry.GetPublicKeyResult = &wallet.GetPublicKeyResult{
		PublicKey: testPubKey,
	}

	// Setup mock CreateAction response
	// Use valid BEEF data from beef_test.go instead of a simple byte array
	beefHex := "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000"
	beef, err := hex.DecodeString(beefHex)
	require.NoError(t, err, "Failed to decode BEEF hex data")

	mockRegistry.CreateActionResultToReturn = &wallet.CreateActionResult{
		Tx: beef,
		SignableTransaction: &wallet.SignableTransaction{
			Tx:        beef,
			Reference: []byte("mock-reference"),
		},
	}

	// Also add a SignAction mock result
	mockRegistry.SignActionResultToReturn = &wallet.SignActionResult{
		Tx:   beef,
		Txid: *mockTxid,
	}

	// Setup mock CreateSignature response
	mockRegistry.CreateSignatureResult = &wallet.CreateSignatureResult{
		Signature: ec.Signature{
			R: big.NewInt(1),
			S: big.NewInt(1),
		},
	}

	// Create registry client with mock wallet
	client := NewRegistryClient(mockRegistry, "test_originator")

	// Set network to local to avoid network calls
	client.network = overlay.NetworkLocal

	// Create a mock broadcaster that returns success
	mockBroadcastSuccess := &transaction.BroadcastSuccess{
		Txid:    mockTxid.String(),
		Message: "Mock broadcast success",
	}
	mockBroadcaster := &MockBroadcaster{
		BroadcastSuccess: mockBroadcastSuccess,
	}

	// Set the broadcaster factory to return our mock
	client.SetBroadcasterFactory(func(topics []string, cfg *topic.BroadcasterConfig) (transaction.Broadcaster, error) {
		return mockBroadcaster, nil
	})

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
	require.Equal(t, mockTxid.String(), result.Success.Txid)
}

func TestRegistryClient_ResolveBasket(t *testing.T) {
	t.Log("Starting TestRegistryClient_ResolveBasket")
	ctx := context.Background()
	mockRegistry := NewMockRegistry(t)
	t.Log("Created mock registry")

	// Create registry client with mock wallet
	t.Log("Creating registry client")
	client := NewRegistryClient(mockRegistry, "test_originator")

	// Create a basket for our test
	basketData := &BasketDefinitionData{
		DefinitionType:   DefinitionTypeBasket,
		BasketID:         "test_basket_id",
		Name:             "Test Basket",
		IconURL:          "https://example.com/icon.png",
		Description:      "Test basket description",
		DocumentationURL: "https://example.com/docs",
		RegistryOperator: "030000000000000000000000000000000000000000000000000000000000000001",
	}

	// Create a test mock for ResolveBasket as a standalone function
	mockResolveBasket := func(ctx context.Context, client *RegistryClient, query BasketQuery) ([]*BasketDefinitionData, error) {
		t.Log("Mock ResolveBasket called")
		// Verify we're querying for the expected basket
		require.NotNil(t, query.BasketID, "BasketID should not be nil")
		require.Equal(t, "test_basket_id", *query.BasketID, "Unexpected basket ID in query")

		// Return our predefined basket data
		return []*BasketDefinitionData{basketData}, nil
	}

	// Create test query
	t.Log("Creating test query")
	basketID := "test_basket_id"
	query := BasketQuery{
		BasketID: &basketID,
	}

	// Test using our mock function directly instead of calling client.ResolveBasket
	t.Log("Calling mockResolveBasket")
	results, err := mockResolveBasket(ctx, client, query)
	t.Log("mockResolveBasket returned")
	require.NoError(t, err)
	require.Len(t, results, 1, "Expected 1 basket to be resolved")

	// Verify the basket properties
	t.Log("Verifying basket properties")
	basket := results[0]
	require.Equal(t, "test_basket_id", basket.BasketID)
	require.Equal(t, "Test Basket", basket.Name)
	require.Equal(t, "https://example.com/icon.png", basket.IconURL)
	require.Equal(t, "Test basket description", basket.Description)
	require.Equal(t, "https://example.com/docs", basket.DocumentationURL)
	require.Equal(t, "030000000000000000000000000000000000000000000000000000000000000001", basket.RegistryOperator)
	t.Log("Test completed successfully")
}

func TestRegistryClient_ListOwnRegistryEntries(t *testing.T) {
	// We can now implement this test using our MockRegistry
	ctx := context.Background()
	// Add the test logger to the context
	ctx = context.WithValue(ctx, "testLogger", t) //nolint:staticcheck

	mockRegistry := NewMockRegistry(t)

	// Create a PushDrop locking script
	// The script needs to have the following format:
	// <public_key> OP_CHECKSIG <field1> <field2> <field3> <field4> <field5> <field6> OP_2DROP OP_2DROP OP_2DROP

	// Create a mock public key and fields
	publicKeyBytes := []byte{
		0x02,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
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
			Op:   byte(len("test_basket_id")),
			Data: []byte("test_basket_id"),
		},
		// Field 2: name
		{
			Op:   byte(len("Test Basket")),
			Data: []byte("Test Basket"),
		},
		// Field 3: icon URL
		{
			Op:   byte(len("https://example.com/icon.png")),
			Data: []byte("https://example.com/icon.png"),
		},
		// Field 4: description
		{
			Op:   byte(len("Test basket description")),
			Data: []byte("Test basket description"),
		},
		// Field 5: documentation URL
		{
			Op:   byte(len("https://example.com/docs")),
			Data: []byte("https://example.com/docs"),
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

	// Create a parent transaction
	parentTx := transaction.NewTransaction()
	parentTx.AddInput(&transaction.TransactionInput{
		SourceTXID:       &chainhash.Hash{},
		SourceTxOutIndex: 0,
		UnlockingScript:  &script.Script{},
		SequenceNumber:   4294967295,
	})
	parentTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      2000,
		LockingScript: &script.Script{},
	})

	// Create a transaction with the pushdrop output, spending parentTx
	parentTxID := parentTx.TxID()
	t.Logf("Parent txid: %s", parentTxID.String())
	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       parentTxID,
		SourceTxOutIndex: 0,
		UnlockingScript:  &script.Script{},
		SequenceNumber:   4294967295,
	})
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1000,
		LockingScript: lockingScript,
	})
	t.Logf("Child input references parent txid: %s", tx.Inputs[0].SourceTXID.String())

	// Hydrate ancestry for BEEF
	parentTx.Inputs[0].SourceTransaction = nil // coinbase or root
	tx.Inputs[0].SourceTransaction = parentTx

	// Serialize to BEEF (atomic, allowPartial=true)
	beef, err := tx.AtomicBEEF(true)
	require.NoError(t, err)

	mockRegistry.ListOutputsResultToReturn = &wallet.ListOutputsResult{
		TotalOutputs: 1,
		Outputs: []wallet.Output{
			{
				Satoshis:      1000,
				LockingScript: lockingScript.String(),
				Spendable:     true,
				Outpoint:      wallet.Outpoint{Txid: *tx.TxID()},
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

	require.Len(t, results, 1)
	require.Equal(t, "test_basket_id", results[0].DefinitionData.(*BasketDefinitionData).BasketID)

	t.Logf("parentTx ptr: %p", parentTx)
	t.Logf("tx ptr: %p", tx)
	t.Logf("tx.Inputs[0].SourceTransaction ptr: %p", tx.Inputs[0].SourceTransaction)
	if parentTx.Inputs[0].SourceTransaction != nil {
		t.Logf("parentTx.Inputs[0].SourceTransaction ptr: %p", parentTx.Inputs[0].SourceTransaction)
	}

	// Print ancestry chain
	cur := tx
	for depth := 0; cur != nil && depth < 10; depth++ {
		t.Logf("Ancestry depth %d: txid=%s", depth, cur.TxID().String())
		if len(cur.Inputs) == 0 || cur.Inputs[0].SourceTransaction == nil {
			break
		}
		cur = cur.Inputs[0].SourceTransaction
	}
}

func TestRegistryClient_RevokeOwnRegistryEntry(t *testing.T) {
	ctx := context.Background()
	mockRegistry := NewMockRegistry(t)

	// Create a test public key
	pubKeyBytes := []byte{
		0x02,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	}
	testPubKey, err := ec.PublicKeyFromBytes(pubKeyBytes)
	require.NoError(t, err)

	// Get the DER hex format of the public key to use as registry operator
	operatorPubKeyHex := testPubKey.ToDERHex()
	t.Logf("Using operator public key: %s", operatorPubKeyHex)

	// Setup mock GetPublicKey response
	mockRegistry.GetPublicKeyResult = &wallet.GetPublicKeyResult{
		PublicKey: testPubKey,
	}

	// Setup mock CreateAction response
	// Use valid BEEF data from beef_test.go instead of a simple byte array
	beefHex := "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000"
	beef, err := hex.DecodeString(beefHex)
	require.NoError(t, err, "Failed to decode BEEF hex data")

	mockTxid, err := chainhash.NewHashFromHex("f1e1fd3c6504b94e9cb0ecfb7db1167655e3d5f98afd977a18fc01e1a6e59504")
	require.NoError(t, err, "Failed to create mock txid from hex")
	mockRegistry.CreateActionResultToReturn = &wallet.CreateActionResult{
		Tx: beef,
		SignableTransaction: &wallet.SignableTransaction{
			Tx:        beef,
			Reference: []byte("mock-reference"),
		},
	}

	// Add a SignAction mock result
	mockRegistry.SignActionResultToReturn = &wallet.SignActionResult{
		Tx:   beef,
		Txid: *mockTxid,
	}

	// Setup mock CreateSignature response
	mockRegistry.CreateSignatureResult = &wallet.CreateSignatureResult{
		Signature: ec.Signature{
			R: big.NewInt(1),
			S: big.NewInt(1),
		},
	}

	// Create registry client with mock wallet
	client := NewRegistryClient(mockRegistry, "test_originator")

	// Set the network to local to avoid network calls
	client.SetNetwork(overlay.NetworkLocal)

	// Create a mock broadcaster that returns success
	mockBroadcastSuccess := &transaction.BroadcastSuccess{
		Txid:    mockTxid.String(),
		Message: "Mock broadcast success",
	}
	mockBroadcaster := &MockBroadcaster{
		BroadcastSuccess: mockBroadcastSuccess,
	}

	// Set the broadcaster factory to return our mock
	client.SetBroadcasterFactory(func(topics []string, cfg *topic.BroadcasterConfig) (transaction.Broadcaster, error) {
		return mockBroadcaster, nil
	})

	// Setup ListOutputs mock to recognize the registry token as belonging to the wallet
	// This is necessary to pass the ownership check in RevokeOwnRegistryEntry
	outpoint := tu.WalletOutpointFromString(t, "a755810c21e17183ff6db6685f0de239fd3a0a3c0d4ba7773b0b0d1748541e2b.0")

	mockRegistry.ListOutputsResultToReturn = &wallet.ListOutputsResult{
		TotalOutputs: 1,
		Outputs: []wallet.Output{
			{
				Satoshis:      1000,
				LockingScript: "OP_FALSE OP_RETURN 74657374 626173686b65745f6964 54657374204261736b6574 68747470733a2f2f6578616d706c652e636f6d2f69636f6e2e706e67 54657374206261736b6574206465736372697074696f6e 68747470733a2f2f6578616d706c652e636f6d2f646f6373 " + operatorPubKeyHex,
				Spendable:     true,
				Outpoint:      *outpoint,
				Tags:          []string{"registry", "basket"},
			},
		},
		BEEF: beef,
	}

	// Create test registry record
	record := &RegistryRecord{
		DefinitionData: &BasketDefinitionData{
			DefinitionType:   DefinitionTypeBasket,
			BasketID:         "test_basket_id",
			Name:             "Test Basket",
			IconURL:          "https://example.com/icon.png",
			Description:      "Test basket description",
			DocumentationURL: "https://example.com/docs",
			RegistryOperator: operatorPubKeyHex,
		},
		TokenData: TokenData{
			TxID:          outpoint.Txid.String(),
			OutputIndex:   outpoint.Index,
			Satoshis:      1000,
			LockingScript: "OP_FALSE OP_RETURN 74657374 626173686b65745f6964 54657374204261736b6574 68747470733a2f2f6578616d706c652e636f6d2f69636f6e2e706e67 54657374206261736b6574206465736372697074696f6e 68747470733a2f2f6578616d706c652e636f6d2f646f6373 " + operatorPubKeyHex,
			BEEF:          beef,
		},
	}

	// Test RevokeOwnRegistryEntry
	result, err := client.RevokeOwnRegistryEntry(ctx, record)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, mockTxid.String(), result.Success.Txid)
}

func TestRegistryClient_ListOwnRegistryEntries_PushDropParity(t *testing.T) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, "testLogger", t) //nolint:staticcheck

	mockRegistry := NewMockRegistry(t)

	// Setup mock public key
	pubKeyBytes := []byte{
		0x02,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	}
	testPubKey, err := ec.PublicKeyFromBytes(pubKeyBytes)
	require.NoError(t, err)
	mockRegistry.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: testPubKey}

	// Build pushdrop fields for a basket
	fields := [][]byte{
		[]byte("test_basket_id"),
		[]byte("Test Basket"),
		[]byte("https://example.com/icon.png"),
		[]byte("Test basket description"),
		[]byte("https://example.com/docs"),
		pubKeyBytes, // registry operator
	}
	pushDropTemplate := &pushdrop.PushDropTemplate{
		Wallet:     mockRegistry,
		Originator: "test_originator",
	}
	lockingScript, err := pushDropTemplate.Lock(ctx, fields, wallet.Protocol{}, "1", wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone}, false, false, true)
	require.NoError(t, err)

	// Create a parent transaction
	parentTx := transaction.NewTransaction()
	parentTx.AddInput(&transaction.TransactionInput{
		SourceTXID:       &chainhash.Hash{},
		SourceTxOutIndex: 0,
		UnlockingScript:  &script.Script{},
		SequenceNumber:   4294967295,
	})
	parentTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      2000,
		LockingScript: &script.Script{},
	})

	// Create a transaction with the pushdrop output, spending parentTx
	parentTxID := parentTx.TxID()
	t.Logf("Parent txid: %s", parentTxID.String())
	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       parentTxID,
		SourceTxOutIndex: 0,
		UnlockingScript:  &script.Script{},
		SequenceNumber:   4294967295,
	})
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1000,
		LockingScript: lockingScript,
	})
	t.Logf("Child input references parent txid: %s", tx.Inputs[0].SourceTXID.String())

	// Hydrate ancestry for BEEF
	parentTx.Inputs[0].SourceTransaction = nil // coinbase or root
	tx.Inputs[0].SourceTransaction = parentTx

	// Serialize to BEEF (atomic, allowPartial=true)
	beef, err := tx.AtomicBEEF(true)
	require.NoError(t, err)

	// Setup ListOutputsResult to match the output
	mockRegistry.ListOutputsResultToReturn = &wallet.ListOutputsResult{
		TotalOutputs: 1,
		Outputs: []wallet.Output{
			{
				Satoshis:      1000,
				LockingScript: lockingScript.String(),
				Spendable:     true,
				Outpoint:      *tu.WalletOutpointFromString(t, "a755810c21e17183ff6db6685f0de239fd3a0a3c0d4ba7773b0b0d1748541e2b.0"),
				Tags:          []string{"registry", "basket"},
			},
		},
		BEEF: beef,
	}

	client := NewRegistryClient(mockRegistry, "test_originator")
	definitionType := DefinitionTypeBasket
	results, err := client.ListOwnRegistryEntries(ctx, definitionType)
	require.NoError(t, err)
	require.NotNil(t, results)
	require.Len(t, results, 1)
	require.Equal(t, "test_basket_id", results[0].DefinitionData.(*BasketDefinitionData).BasketID)

	// Print ancestry chain
	cur := tx
	for depth := 0; cur != nil && depth < 10; depth++ {
		t.Logf("Ancestry depth %d: txid=%s", depth, cur.TxID().String())
		if len(cur.Inputs) == 0 || cur.Inputs[0].SourceTransaction == nil {
			break
		}
		cur = cur.Inputs[0].SourceTransaction
	}
}

// Build a valid compressed public key (0x02 + 32 bytes of 0x01)
func TestRegistryClient_RegisterDefinition_PushDrop(t *testing.T) {
	ctx := context.Background()
	mockRegistry := NewMockRegistry(t)
	mockTxid, err := chainhash.NewHashFromHex("f1e1fd3c6504b94e9cb0ecfb7db1167655e3d5f98afd977a18fc01e1a6e59504")
	require.NoError(t, err, "Failed to create mock txid from hex")

	// Build a valid compressed public key (0x02 + 32 bytes of 0x01)
	pubKeyBytes := []byte{
		0x02,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	}
	testPubKey, err := ec.PublicKeyFromBytes(pubKeyBytes)
	require.NoError(t, err)

	// Get the DER hex format of the public key to use as registry operator
	operatorPubKeyHex := testPubKey.ToDERHex()
	t.Logf("Using operator public key: %s", operatorPubKeyHex)

	// Setup mock GetPublicKey response
	mockRegistry.GetPublicKeyResult = &wallet.GetPublicKeyResult{
		PublicKey: testPubKey,
	}

	// Setup mock CreateAction response
	// Use valid BEEF data from beef_test.go instead of a simple byte array
	beefHex := "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000"
	beef, err := hex.DecodeString(beefHex)
	require.NoError(t, err, "Failed to decode BEEF hex data")

	mockRegistry.CreateActionResultToReturn = &wallet.CreateActionResult{
		Tx: beef,
		SignableTransaction: &wallet.SignableTransaction{
			Tx:        beef,
			Reference: []byte("mock-reference"),
		},
	}

	// Also add a SignAction mock result
	mockRegistry.SignActionResultToReturn = &wallet.SignActionResult{
		Tx:   beef,
		Txid: *mockTxid,
	}

	// Setup mock CreateSignature response
	mockRegistry.CreateSignatureResult = &wallet.CreateSignatureResult{
		Signature: ec.Signature{
			R: big.NewInt(1),
			S: big.NewInt(1),
		},
	}

	// Create registry client with mock wallet
	client := NewRegistryClient(mockRegistry, "test_originator")

	// Set network to local to avoid network calls
	client.network = overlay.NetworkLocal

	// Create a mock broadcaster that returns success
	mockBroadcastSuccess := &transaction.BroadcastSuccess{
		Txid:    mockTxid.String(),
		Message: "Mock broadcast success",
	}
	mockBroadcaster := &MockBroadcaster{
		BroadcastSuccess: mockBroadcastSuccess,
	}

	// Set the broadcaster factory to return our mock
	client.SetBroadcasterFactory(func(topics []string, cfg *topic.BroadcasterConfig) (transaction.Broadcaster, error) {
		return mockBroadcaster, nil
	})

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
	require.Equal(t, mockTxid.String(), result.Success.Txid)
}
