package kvstore_test

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/bsv-blockchain/go-sdk/kvstore"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

// --- Test Helpers ---

// TAG_KEY_PREFIX defines the prefix used for tagging keys in outputs
const TAG_KEY_PREFIX = "kv:"

// Constants for mock values matching TypeScript tests
const (
	TestLockingScriptHex   = "mockLockingScriptHex"
	TestUnlockingScriptHex = "mockUnlockingScriptHex"
	TestRawValue           = "myTestDataValue"
	TestKey                = "myTestKey"
	TestContext            = "test-kv-context"
)

// CreateActionNameWithContext generates the action name for a KV store operation
func CreateActionNameWithContext(originator, context, key, value string) string {
	return fmt.Sprintf("%s:%s:%s:%s", originator, context, key, value)
}

// NewPushDataScriptFromItems creates a script from a slice of byte arrays
func NewPushDataScriptFromItems(items [][]byte) string {
	scriptBytes, err := script.EncodePushDatas(items)
	if err != nil {
		panic(fmt.Sprintf("Failed to encode push data: %v", err))
	}
	return fmt.Sprintf("%x", scriptBytes)
}

// CreateTagForKey creates a tag string for a specific key
func CreateTagForKey(key string) string {
	return fmt.Sprintf("%s%s", TAG_KEY_PREFIX, key)
}

// setupTestKVStore creates a test KV store with a mock wallet
func setupTestKVStore(t *testing.T) (*kvstore.LocalKVStore, *wallet.TestWallet) {
	mockTxID := tu.GetByte32FromString("mockTxId")

	testWallet := wallet.NewTestWalletForRandomKey(t)

	testWallet.ExpectOriginator("test")

	testWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		Txid: mockTxID,
	})

	testWallet.OnSignAction().ReturnSuccess(&wallet.SignActionResult{
		Txid: mockTxID,
	})

	testWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{},
	})

	testWallet.OnRelinquishOutput().ReturnSuccess(&wallet.RelinquishOutputResult{
		Relinquished: true,
	})

	testWallet.OnGetPublicKey().ReturnSuccess(&wallet.GetPublicKeyResult{
		PublicKey: &ec.PublicKey{
			X: big.NewInt(1),
			Y: big.NewInt(2),
		},
	})

	store, err := kvstore.NewLocalKVStore(kvstore.KVStoreConfig{
		Wallet:     testWallet,
		Originator: "test",
		Context:    "test-context",
		Encrypt:    false,
	})
	require.NoError(t, err)
	require.NotNil(t, store)
	return store, testWallet
}

// func TestLocalKVStoreGet_HasData(t *testing.T) {
// 	t.Parallel()

// 	store, mockWallet := setupTestKVStore(t)
// 	key := "key1"
// 	value := "value1"
// 	tag := CreateTagForKey(key)

// 	// Mock the wallet response
// 	mockWallet.ListOutputsResultToReturn = &wallet.ListOutputsResult{
// 		Outputs: []wallet.Output{
// 			{
// 				Satoshis:      100,
// 				LockingScript: NewPushDataScriptFromItems([][]byte{[]byte(key), []byte(value)}),
// 				Tags:          []string{tag},
// 				Outpoint:      "someTxId:0",
// 			},
// 		},
// 	}

// 	// Perform the Get operation
// 	result, err := store.Get(context.Background(), key, "")
// 	require.NoError(t, err)
// 	require.NotNil(t, result)
// 	require.Equal(t, value, result)
// }

// func TestLocalKVStoreGet_EmptyResult(t *testing.T) {
// 	t.Parallel()

// 	store, mockWallet := setupTestKVStore(t)
// 	key := "key1"

// 	// Mock the wallet response with no outputs
// 	mockWallet.ListOutputsResultToReturn = &wallet.ListOutputsResult{
// 		Outputs: []wallet.Output{},
// 	}

// 	// Perform the Get operation
// 	result, err := store.Get(context.Background(), key, "")
// 	require.Error(t, err)
// 	require.Equal(t, "", result)
// 	require.True(t, errors.Is(err, kvstore.ErrNotFound))
// }

func TestLocalKVStoreGet_WalletError(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)
	key := "key1"
	expectedError := errors.New("wallet error")

	// Mock the wallet to return an error
	mockWallet.OnListOutputs().ReturnError(expectedError)

	// Perform the Get operation
	result, err := store.Get(context.Background(), key, "")
	require.Error(t, err)
	require.Equal(t, "", result)
	require.ErrorContains(t, err, expectedError.Error())
}

func TestLocalKVStoreSet_Success(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)
	key := "key1"
	value := "value1"

	// Setup the success case
	mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		Txid: tu.GetByte32FromString("txId"),
	})

	// Perform the Set operation
	_, err := store.Set(context.Background(), key, value)
	require.NoError(t, err)
}

func TestLocalKVStoreSet_WalletError(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)
	key := "key1"
	value := "value1"
	expectedError := errors.New("wallet error")

	// Mock the wallet to return an error
	mockWallet.OnCreateAction().ReturnError(expectedError)

	// Perform the Set operation
	_, err := store.Set(context.Background(), key, value)
	require.Error(t, err)
	require.ErrorContains(t, err, expectedError.Error())
}

// func TestLocalKVStoreRemove_Success(t *testing.T) {
// 	t.Parallel()

// 	store, mockWallet := setupTestKVStore(t)
// 	key := "key1"
// 	value := "value1"
// 	tag := CreateTagForKey(key)
// 	outpoint := "someTxId:0"

// 	// Mock the wallet response for ListOutputs
// 	mockWallet.ListOutputsResultToReturn = &wallet.ListOutputsResult{
// 		Outputs: []wallet.Output{
// 			{
// 				Satoshis:      100,
// 				LockingScript: NewPushDataScriptFromItems([][]byte{[]byte(key), []byte(value)}),
// 				Tags:          []string{tag},
// 				Outpoint:      outpoint,
// 			},
// 		},
// 	}

// 	// Mock the wallet response for RelinquishOutput
// 	mockWallet.RelinquishOutputResultToReturn = &wallet.RelinquishOutputResult{
// 		Relinquished: true,
// 	}

// 	// Perform the Remove operation
// 	_, err := store.Remove(context.Background(), key)
// 	require.NoError(t, err)

// 	// Verify RelinquishOutput was called
// 	require.Equal(t, 1, mockWallet.RelinquishOutputCalledCount)
// }

// func TestLocalKVStoreRemove_NotFound(t *testing.T) {
// 	t.Parallel()

// 	store, mockWallet := setupTestKVStore(t)
// 	key := "key1"

// 	// Mock the wallet response with no outputs
// 	mockWallet.ListOutputsResultToReturn = &wallet.ListOutputsResult{
// 		Outputs: []wallet.Output{},
// 	}

// 	// Perform the Remove operation
// 	_, err := store.Remove(context.Background(), key)
// 	require.Error(t, err)
// 	require.True(t, errors.Is(err, kvstore.ErrNotFound))

// 	// Verify RelinquishOutput was not called
// 	require.Equal(t, 0, mockWallet.RelinquishOutputCalledCount)
// }

func TestLocalKVStoreRemove_ListOutputsError(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)
	key := "key1"
	expectedError := errors.New("wallet error")

	// Mock the wallet to return an error
	mockWallet.OnListOutputs().ReturnError(expectedError)

	// ensure RelinquishOutput was not called
	mockWallet.OnRelinquishOutput().Do(func(ctx context.Context, args wallet.RelinquishOutputArgs, originator string) (*wallet.RelinquishOutputResult, error) {
		require.Fail(t, "RelinquishOutput should not be called")
		return nil, nil
	})

	// Perform the Remove operation
	_, err := store.Remove(context.Background(), key)

	require.Error(t, err)
	require.ErrorContains(t, err, expectedError.Error())
}

// func TestLocalKVStoreRemove_RelinquishError(t *testing.T) {
// 	t.Parallel()

// 	store, mockWallet := setupTestKVStore(t)
// 	key := "key1"
// 	value := "value1"
// 	tag := CreateTagForKey(key)
// 	outpoint := "someTxId:0"
// 	expectedError := errors.New("relinquish error")

// 	// Mock the wallet response for ListOutputs
// 	mockWallet.ListOutputsResultToReturn = &wallet.ListOutputsResult{
// 		Outputs: []wallet.Output{
// 			{
// 				Satoshis:      100,
// 				LockingScript: NewPushDataScriptFromItems([][]byte{[]byte(key), []byte(value)}),
// 				Tags:          []string{tag},
// 				Outpoint:      outpoint,
// 			},
// 		},
// 	}

// 	// Mock the wallet to return an error for RelinquishOutput
// 	mockWallet.RelinquishOutputError = expectedError

// 	// Perform the Remove operation
// 	_, err := store.Remove(context.Background(), key)
// 	require.Error(t, err)
// 	require.ErrorContains(t, err, expectedError.Error())

// 	// Verify RelinquishOutput was called
// 	require.Equal(t, 1, mockWallet.RelinquishOutputCalledCount)
// }

// func TestNewLocalKVStore_InvalidRetentionPeriod(t *testing.T) {
// 	t.Parallel()

// 	mockWallet := wallet.NewTestWallet(t)

// 	// Test invalid retention period
// 	store, err := kvstore.NewLocalKVStore(kvstore.KVStoreConfig{
// 		Wallet:     mockWallet,
// 		Originator: "test",
// 		Context:    "test-context",
// 		Encrypt:    false,
// 	})
// 	require.Error(t, err)
// 	require.Nil(t, store)
// 	require.Equal(t, kvstore.ErrInvalidRetentionPeriod, err)
// }

func TestNewLocalKVStore_EmptyContext(t *testing.T) {
	t.Parallel()

	mockWallet := wallet.NewTestWalletForRandomKey(t)

	// Test empty context
	store, err := kvstore.NewLocalKVStore(kvstore.KVStoreConfig{
		Wallet:     mockWallet,
		Originator: "test",
		Context:    "", // Invalid
		Encrypt:    false,
	})
	require.Error(t, err)
	require.Nil(t, store)
	require.Equal(t, err, kvstore.ErrEmptyContext)
}

func TestLocalKVStore_EmptyKey(t *testing.T) {
	t.Parallel()

	store, _ := setupTestKVStore(t)

	// Test empty key for Get
	result, err := store.Get(context.Background(), "", "")
	require.Error(t, err)
	require.Equal(t, "", result)
	require.Equal(t, kvstore.ErrInvalidKey, err)

	// Test empty key for Set
	_, err = store.Set(context.Background(), "", "value")
	require.Error(t, err)
	require.Equal(t, kvstore.ErrInvalidKey, err)

	// Test empty key for Remove
	_, err = store.Remove(context.Background(), "")
	require.Error(t, err)
	require.Equal(t, kvstore.ErrInvalidKey, err)
}

func TestLocalKVStore_EmptyValue(t *testing.T) {
	t.Parallel()

	store, _ := setupTestKVStore(t)

	// Test empty value for Set
	_, err := store.Set(context.Background(), "key", "")
	require.Error(t, err)
	require.Equal(t, kvstore.ErrInvalidValue, err)
}

// Comment out or remove all usages of store.List and List-related tests
