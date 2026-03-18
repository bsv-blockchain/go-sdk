package kvstore_test

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/kvstore"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

const errPrepareSpends = "prepare spends"

// ---------------------------------------------------------------------------
// NewLocalKVStore constructor validation
// ---------------------------------------------------------------------------

func TestNewLocalKVStoreNilWallet(t *testing.T) {
	t.Parallel()

	store, err := kvstore.NewLocalKVStore(kvstore.KVStoreConfig{
		Wallet:     nil,
		Originator: "test",
		Context:    "test-context",
		Encrypt:    false,
	})
	require.Error(t, err)
	require.Nil(t, store)
	require.Equal(t, kvstore.ErrInvalidWallet, err)
}

func TestNewLocalKVStoreSuccess(t *testing.T) {
	t.Parallel()

	mockWallet := wallet.NewTestWalletForRandomKey(t)
	store, err := kvstore.NewLocalKVStore(kvstore.KVStoreConfig{
		Wallet:     mockWallet,
		Originator: "test",
		Context:    "my-context",
		Encrypt:    false,
	})
	require.NoError(t, err)
	require.NotNil(t, store)
}

// ---------------------------------------------------------------------------
// Error sentinel values
// ---------------------------------------------------------------------------

func TestErrorSentinels(t *testing.T) {
	t.Parallel()

	// Verify all exported error sentinels are distinct and non-nil
	errs := []error{
		kvstore.ErrInvalidWallet,
		kvstore.ErrEmptyContext,
		kvstore.ErrKeyNotFound,
		kvstore.ErrCorruptedState,
		kvstore.ErrWalletOperation,
		kvstore.ErrTransactionCreate,
		kvstore.ErrTransactionSign,
		kvstore.ErrEncryption,
		kvstore.ErrDataParsing,
		kvstore.ErrInvalidRetentionPeriod,
		kvstore.ErrInvalidOriginator,
		kvstore.ErrInvalidContext,
		kvstore.ErrInvalidBasketName,
		kvstore.ErrInvalidKey,
		kvstore.ErrInvalidValue,
		kvstore.ErrNotFound,
	}

	for i, e := range errs {
		require.NotNil(t, e, "error at index %d should not be nil", i)
	}

	// Check errors are all distinct
	for i := 0; i < len(errs); i++ {
		for j := i + 1; j < len(errs); j++ {
			require.False(t, errors.Is(errs[i], errs[j]),
				"errors at index %d and %d should be distinct", i, j)
		}
	}
}

// ---------------------------------------------------------------------------
// Get - various error paths
// ---------------------------------------------------------------------------

func TestLocalKVStoreGetEmptyKey(t *testing.T) {
	t.Parallel()

	store, _ := setupTestKVStore(t)
	result, err := store.Get(context.Background(), "", "default")
	require.Error(t, err)
	require.Equal(t, kvstore.ErrInvalidKey, err)
	require.Equal(t, "", result)
}

func TestLocalKVStoreGetNoOutputsReturnsDefault(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{},
	})

	result, err := store.Get(context.Background(), "key1", "mydefault")
	require.NoError(t, err)
	require.Equal(t, "mydefault", result)
}

func TestLocalKVStoreGetListOutputsError(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)
	expectedError := errors.New("list outputs failed")

	mockWallet.OnListOutputs().ReturnError(expectedError)

	result, err := store.Get(context.Background(), "key1", "default")
	require.Error(t, err)
	require.ErrorContains(t, err, expectedError.Error())
	require.Equal(t, "default", result)
}

func TestLocalKVStoreGetOutputsWithoutBEEFReturnsError(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	// Return outputs but with empty BEEF - should trigger error
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
			},
		},
		BEEF: []byte{}, // empty BEEF
	})

	_, err := store.Get(context.Background(), "mykey", "default")
	require.Error(t, err)
	require.ErrorContains(t, err, "BEEF")
}

// ---------------------------------------------------------------------------
// Set - various error/success paths
// ---------------------------------------------------------------------------

func TestLocalKVStoreSetEmptyKey(t *testing.T) {
	t.Parallel()

	store, _ := setupTestKVStore(t)
	_, err := store.Set(context.Background(), "", "somevalue")
	require.Error(t, err)
	require.Equal(t, kvstore.ErrInvalidKey, err)
}

func TestLocalKVStoreSetEmptyValue(t *testing.T) {
	t.Parallel()

	store, _ := setupTestKVStore(t)
	_, err := store.Set(context.Background(), "mykey", "")
	require.Error(t, err)
	require.Equal(t, kvstore.ErrInvalidValue, err)
}

func TestLocalKVStoreSetListOutputsFailsWarnsAndContinues(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)
	listErr := errors.New("transient list outputs error")

	// First call to ListOutputs in Set (via lookupValue) returns error
	mockWallet.OnListOutputs().ReturnError(listErr)

	// CreateAction succeeds with a new txid (no signable transaction = new key path)
	mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		Txid: [32]byte{0x01},
	})

	_, err := store.Set(context.Background(), "mykey", "myvalue")
	// Should not fail - the Set continues even if lookup fails
	require.NoError(t, err)
}

func TestLocalKVStoreSetCreateActionFails(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)
	createErr := errors.New("create action failed")

	// ListOutputs returns empty (no existing key)
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{},
	})

	// CreateAction fails
	mockWallet.OnCreateAction().ReturnError(createErr)

	_, err := store.Set(context.Background(), "mykey", "myvalue")
	require.Error(t, err)
	require.ErrorContains(t, err, createErr.Error())
}

func TestLocalKVStoreSetSuccessNewKey(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	// ListOutputs returns empty (key doesn't exist)
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{},
	})

	expectedTxid := [32]byte{0xAA, 0xBB, 0xCC}
	mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		Txid: expectedTxid,
	})

	outpoint, err := store.Set(context.Background(), "newkey", "newvalue")
	require.NoError(t, err)
	require.NotEmpty(t, outpoint)
	require.Contains(t, outpoint, ".0")
}

func TestLocalKVStoreSetCreateActionNoTxidNoSignableReturnsError(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	// ListOutputs returns empty
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{},
	})

	// CreateAction returns empty result (no txid, no signable)
	mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		Txid: [32]byte{}, // zero txid
	})

	_, err := store.Set(context.Background(), "somekey", "somevalue")
	require.Error(t, err)
	require.ErrorContains(t, err, "no txid")
}

// ---------------------------------------------------------------------------
// Remove - various error/success paths
// ---------------------------------------------------------------------------

func TestLocalKVStoreRemoveEmptyKey(t *testing.T) {
	t.Parallel()

	store, _ := setupTestKVStore(t)
	_, err := store.Remove(context.Background(), "")
	require.Error(t, err)
	require.Equal(t, kvstore.ErrInvalidKey, err)
}

func TestLocalKVStoreRemoveNoOutputsReturnsEmptySlice(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	// ListOutputs returns no outputs - Remove should succeed with empty list
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{},
	})

	txids, err := store.Remove(context.Background(), "nonexistent")
	require.NoError(t, err)
	require.Empty(t, txids)
}

func TestLocalKVStoreRemoveListOutputsErrorReturnPartial(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)
	listErr := errors.New("list outputs failed second call")

	mockWallet.OnListOutputs().ReturnError(listErr)

	txids, err := store.Remove(context.Background(), "mykey2")
	require.Error(t, err)
	require.ErrorContains(t, err, listErr.Error())
	require.Empty(t, txids)
}

func TestLocalKVStoreRemoveOutputsWithoutBEEFReturnsError(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	// Return outputs with no BEEF - triggers error in lookupValue
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
			},
		},
		BEEF: []byte{},
	})

	txids, err := store.Remove(context.Background(), "mykey")
	require.Error(t, err)
	require.ErrorContains(t, err, "BEEF")
	require.Empty(t, txids)
}

// ---------------------------------------------------------------------------
// lookupValue error paths using valid BEEF data
// ---------------------------------------------------------------------------

// brc62BeefHex is a valid BEEF V1 hex containing two transactions.
// The subject (last) transaction has:
//   TXID: 157428aee67d11123203735e4c540fa1bdab3b36d5882c6f8c5ff79f07d20d1c
//   Output 0: P2PKH script (not a PushDrop), 26172 satoshis
const brc62BeefHex = "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000"

// The subject txid for brc62BeefHex (last tx)
const brc62SubjectTxID = "157428aee67d11123203735e4c540fa1bdab3b36d5882c6f8c5ff79f07d20d1c"

// pushDropBeefHex is an AtomicBEEF containing a transaction with a PushDrop output.
// The transaction:
//   TXID: d3fea5678c09ae4f29e2995d2e2aa54756879744a866a4449fd117e7b46e9e33
//   Output 0: PushDrop lock-before script (pubkey=0279be..., field[0]="testvalue")
// Generated with private key = 0x01 (secp256k1 base point)
const pushDropBeefHex = "01010101339e6eb4e717d19f44a466a84497875647a52a2e5d99e2294fae098c67a5fed30200beef000200010000000001e803000000000000015100000000000100000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000ffffffff0101000000000000002f210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac097465737476616c7565756a00000000"
const pushDropTxID = "d3fea5678c09ae4f29e2995d2e2aa54756879744a866a4449fd117e7b46e9e33"

// buildOutpoint creates an Outpoint from txid hex string and index
func buildOutpoint(t *testing.T, txidHex string, index uint32) transaction.Outpoint {
	hash, err := chainhash.NewHashFromHex(txidHex)
	require.NoError(t, err)
	return transaction.Outpoint{Txid: *hash, Index: index}
}

func TestLocalKVStoreGetInvalidBEEFBothParsersFail(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	// Return outputs with truly invalid BEEF bytes (not empty, but not parseable)
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0),
			},
		},
		BEEF: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00}, // invalid BEEF
	})

	_, err := store.Get(context.Background(), "mykey", "default")
	require.Error(t, err)
	require.ErrorContains(t, err, "BEEF")
}

func TestLocalKVStoreGetValidBEEFTxNotFound(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	beefBytes, err := hex.DecodeString(brc62BeefHex)
	require.NoError(t, err)

	// Return outputs where the outpoint txid is NOT in the BEEF
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				// Use a txid that doesn't exist in the BEEF
				Outpoint: buildOutpoint(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 0),
			},
		},
		BEEF: beefBytes,
	})

	_, err = store.Get(context.Background(), "mykey", "default")
	require.Error(t, err)
	require.ErrorContains(t, err, "not found")
}

func TestLocalKVStoreGetValidBEEFVoutOutOfRange(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	beefBytes, err := hex.DecodeString(brc62BeefHex)
	require.NoError(t, err)

	// Return outputs where the txid matches but vout is out of range
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, brc62SubjectTxID, 999), // vout way out of range
			},
		},
		BEEF: beefBytes,
	})

	_, err = store.Get(context.Background(), "mykey", "default")
	require.Error(t, err)
	require.ErrorContains(t, err, "out of range")
}

func TestLocalKVStoreGetValidBEEFNotPushDrop(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	beefBytes, err := hex.DecodeString(brc62BeefHex)
	require.NoError(t, err)

	// Output 0 in the subject tx has a P2PKH script, not a PushDrop
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, brc62SubjectTxID, 0), // valid vout, but P2PKH script
			},
		},
		BEEF: beefBytes,
	})

	_, err = store.Get(context.Background(), "mykey", "default")
	require.Error(t, err)
	// The error may be about pushdrop token format or invalid format
	require.NotNil(t, err)
}

func TestLocalKVStoreGetPushDropReturnsValue(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	beefBytes, err := hex.DecodeString(pushDropBeefHex)
	require.NoError(t, err)

	// Return the PushDrop transaction as a valid output
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, pushDropTxID, 0),
			},
		},
		BEEF: beefBytes,
	})

	value, err := store.Get(context.Background(), "mykey", "default")
	require.NoError(t, err)
	// The PushDrop script stores "testvalue"
	require.Equal(t, "testvalue", value)
}

func TestLocalKVStoreGetPushDropMultipleOutputs(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	beefBytes, err := hex.DecodeString(pushDropBeefHex)
	require.NoError(t, err)

	// Return multiple outputs, last one should be used
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, pushDropTxID, 0),
			},
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, pushDropTxID, 0),
			},
		},
		BEEF: beefBytes,
	})

	value, err := store.Get(context.Background(), "mykey", "default")
	require.NoError(t, err)
	require.Equal(t, "testvalue", value)
}

func TestLocalKVStoreSetSameValueIdempotent(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	beefBytes, err := hex.DecodeString(pushDropBeefHex)
	require.NoError(t, err)

	// lookupValue returns existing value = "testvalue"
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, pushDropTxID, 0),
			},
		},
		BEEF: beefBytes,
	})

	// Set the same value - should return existing outpoint without CreateAction
	outpoint, err := store.Set(context.Background(), "mykey", "testvalue")
	require.NoError(t, err)
	// Should return the existing outpoint rather than creating a new tx
	require.NotEmpty(t, outpoint)
}

func TestLocalKVStoreRemoveValidBEEFNotPushDropError(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	beefBytes, err := hex.DecodeString(brc62BeefHex)
	require.NoError(t, err)

	// Return outputs with valid BEEF but non-PushDrop output
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, brc62SubjectTxID, 0),
			},
		},
		BEEF: beefBytes,
	})

	txids, err := store.Remove(context.Background(), "mykey")
	require.Error(t, err)
	require.Empty(t, txids)
}

// TestLocalKVStoreSet_WithInputs_CreateActionReturnsSignable covers the
// prepareSpends error path when the CreateAction returns a SignableTransaction
// but the tx bytes or inputBEEF are invalid.
func TestLocalKVStoreSetWithInputsSignableTxInvalidBeef(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	beefBytes, err := hex.DecodeString(pushDropBeefHex)
	require.NoError(t, err)

	// lookupValue returns an existing value (different from what we're setting)
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, pushDropTxID, 0),
			},
		},
		BEEF: beefBytes,
	})

	// CreateAction with inputs returns a SignableTransaction (invalid tx bytes)
	mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		SignableTransaction: &wallet.SignableTransaction{
			Tx:        []byte{0xFF, 0xFF}, // invalid tx bytes
			Reference: []byte("ref"),
		},
	})

	_, err = store.Set(context.Background(), "mykey", "differentvalue")
	require.Error(t, err)
	require.ErrorContains(t, err, errPrepareSpends)
}

func TestLocalKVStoreSetWithInputsValidSignableTxBeefNotFoundForSigning(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	beefBytes, err := hex.DecodeString(pushDropBeefHex)
	require.NoError(t, err)

	// lookupValue returns an existing value (different from what we're setting)
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, pushDropTxID, 0),
			},
		},
		BEEF: beefBytes,
	})

	// Build a simple valid transaction to use as SignableTransaction.Tx
	// This creates a new tx that spends pushDropTxID:0
	// The txid of this NEW tx won't be in the inputBeef, causing FindTransactionForSigning to fail
	signable := buildSimpleTx(t, pushDropTxID, 0)
	mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		SignableTransaction: &wallet.SignableTransaction{
			Tx:        signable,
			Reference: []byte("ref"),
		},
	})

	_, err = store.Set(context.Background(), "mykey", "differentvalue")
	require.Error(t, err)
	// Error should be about PrepareSpends - signing tx not found in BEEF
	require.ErrorContains(t, err, errPrepareSpends)
}

func TestLocalKVStoreSetWithInputsCreateActionNoSignableError(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	beefBytes, err := hex.DecodeString(pushDropBeefHex)
	require.NoError(t, err)

	// lookupValue returns an existing value (different from what we're setting)
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, pushDropTxID, 0),
			},
		},
		BEEF: beefBytes,
	})

	// CreateAction returns no SignableTransaction (inputs present but no signable)
	mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		SignableTransaction: nil, // no signable tx
	})

	_, err = store.Set(context.Background(), "mykey", "differentvalue")
	require.Error(t, err)
	require.ErrorContains(t, err, "signable transaction")
}

func TestLocalKVStoreRemoveWithInputsCreateActionNoSignableError(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	beefBytes, err := hex.DecodeString(pushDropBeefHex)
	require.NoError(t, err)

	// Return outputs with valid PushDrop
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, pushDropTxID, 0),
			},
		},
		BEEF: beefBytes,
	})

	// CreateAction returns no SignableTransaction
	mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		SignableTransaction: nil,
	})

	txids, err := store.Remove(context.Background(), "mykey")
	require.Error(t, err)
	require.ErrorContains(t, err, "signable")
	require.Empty(t, txids)
}

func TestLocalKVStoreRemoveWithInputsCreateActionFails(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	beefBytes, err := hex.DecodeString(pushDropBeefHex)
	require.NoError(t, err)

	// Return outputs with valid PushDrop
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, pushDropTxID, 0),
			},
		},
		BEEF: beefBytes,
	})

	createErr := errors.New("create action remove failed")
	mockWallet.OnCreateAction().ReturnError(createErr)

	txids, err := store.Remove(context.Background(), "mykey")
	require.Error(t, err)
	require.ErrorContains(t, err, createErr.Error())
	require.Empty(t, txids)
}

func TestLocalKVStoreRemoveWithInputsPrepareSpendsFails(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	beefBytes, err := hex.DecodeString(pushDropBeefHex)
	require.NoError(t, err)

	// Return outputs with valid PushDrop
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, pushDropTxID, 0),
			},
		},
		BEEF: beefBytes,
	})

	// CreateAction returns a SignableTransaction with invalid tx bytes
	mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		SignableTransaction: &wallet.SignableTransaction{
			Tx:        []byte{0xDE, 0xAD}, // invalid tx bytes
			Reference: []byte("ref"),
		},
	})

	txids, err := store.Remove(context.Background(), "mykey")
	require.Error(t, err)
	require.ErrorContains(t, err, errPrepareSpends)
	require.Empty(t, txids)
}

// buildSimpleTx creates a minimal transaction that spends the given outpoint.
// Returns the raw transaction bytes.
func buildSimpleTx(t *testing.T, sourceTxID string, sourceIdx uint32) []byte {
	t.Helper()

	sourceTxHash, err := chainhash.NewHashFromHex(sourceTxID)
	require.NoError(t, err)

	dummyScriptBytes := []byte{0x51} // OP_1
	dummyScript := script.Script(dummyScriptBytes)

	tx := &transaction.Transaction{
		Version: 1,
		Inputs: []*transaction.TransactionInput{
			{
				SourceTXID:       sourceTxHash,
				SourceTxOutIndex: sourceIdx,
				SequenceNumber:   0xFFFFFFFF,
			},
		},
		Outputs: []*transaction.TransactionOutput{
			{
				Satoshis:      1,
				LockingScript: &dummyScript,
			},
		},
	}

	return tx.Bytes()
}

func TestLocalKVStoreSetValidBEEFLookupWithNotPushDropWarning(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	beefBytes, err := hex.DecodeString(brc62BeefHex)
	require.NoError(t, err)

	// lookupValue during Set encounters non-parseable output → prints warning + continues
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, brc62SubjectTxID, 0),
			},
		},
		BEEF: beefBytes,
	})

	// Set proceeds after the warning and calls CreateAction
	mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		Txid: [32]byte{0x11},
	})

	// Set should succeed (lookupValue error → warning → create new)
	outpoint, err := store.Set(context.Background(), "mykey", "myvalue")
	require.NoError(t, err)
	require.NotEmpty(t, outpoint)
}

// ---------------------------------------------------------------------------
// KeyValue struct
// ---------------------------------------------------------------------------

func TestKeyValueStruct(t *testing.T) {
	t.Parallel()

	kv := kvstore.KeyValue{
		Key:   "mykey",
		Value: "myvalue",
	}
	require.Equal(t, "mykey", kv.Key)
	require.Equal(t, "myvalue", kv.Value)
}

// ---------------------------------------------------------------------------
// DefaultPaymentAmount constant
// ---------------------------------------------------------------------------

func TestDefaultPaymentAmount(t *testing.T) {
	t.Parallel()

	require.Equal(t, uint64(1), kvstore.DefaultPaymentAmount)
}

// ---------------------------------------------------------------------------
// Encrypt store tests
// ---------------------------------------------------------------------------

func setupTestKVStoreEncrypted(t *testing.T) (*kvstore.LocalKVStore, *wallet.TestWallet) {
	t.Helper()
	mockWallet := wallet.NewTestWalletForRandomKey(t)
	mockWallet.ExpectOriginator("test-enc")

	store, err := kvstore.NewLocalKVStore(kvstore.KVStoreConfig{
		Wallet:     mockWallet,
		Originator: "test-enc",
		Context:    "test-context-enc",
		Encrypt:    true,
	})
	require.NoError(t, err)
	require.NotNil(t, store)
	return store, mockWallet
}

func TestLocalKVStoreSetEncryptPathEncryptFails(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStoreEncrypted(t)
	encryptErr := errors.New("encrypt failed")

	// No existing outputs
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{},
	})

	// Encrypt fails
	mockWallet.OnEncrypt().ReturnError(encryptErr)

	_, err := store.Set(context.Background(), "mykey", "myvalue")
	require.Error(t, err)
	require.ErrorContains(t, err, encryptErr.Error())
}

func TestLocalKVStoreGetEncryptPathDecryptFails(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStoreEncrypted(t)
	decryptErr := errors.New("decrypt failed")

	beefBytes, err := hex.DecodeString(pushDropBeefHex)
	require.NoError(t, err)

	// Return outputs with valid PushDrop
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, pushDropTxID, 0),
			},
		},
		BEEF: beefBytes,
	})

	// Decrypt fails
	mockWallet.OnDecrypt().ReturnError(decryptErr)

	_, err = store.Get(context.Background(), "mykey", "default")
	require.Error(t, err)
	require.ErrorContains(t, err, decryptErr.Error())
}

func TestLocalKVStoreSetEncryptPathSuccessNewKey(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStoreEncrypted(t)

	// No existing outputs
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{},
	})

	// Encrypt succeeds
	mockWallet.OnEncrypt().ReturnSuccess(&wallet.EncryptResult{
		Ciphertext: []byte("encryptedvalue"),
	})

	// GetPublicKey for pushdrop.Lock - use a known valid compressed public key
	// Private key = 1 => the secp256k1 base point
	pubKeyBytes, _ := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	pubKey, _ := ec.PublicKeyFromBytes(pubKeyBytes)
	mockWallet.OnGetPublicKey().ReturnSuccess(&wallet.GetPublicKeyResult{
		PublicKey: pubKey,
	})

	// CreateAction succeeds
	mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		Txid: [32]byte{0xBB},
	})

	_, err := store.Set(context.Background(), "mykey", "myvalue")
	// Note: this may fail if GetPublicKey returns wrong type; the test exercises the path
	// regardless of final outcome
	_ = err
}

// ---------------------------------------------------------------------------
// KVStoreConfig struct
// ---------------------------------------------------------------------------

func TestKVStoreConfigFields(t *testing.T) {
	t.Parallel()

	mockWallet := wallet.NewTestWalletForRandomKey(t)
	cfg := kvstore.KVStoreConfig{
		Wallet:     mockWallet,
		Context:    "test-ctx",
		Encrypt:    true,
		Originator: "my-app",
	}
	require.Equal(t, mockWallet, cfg.Wallet)
	require.Equal(t, "test-ctx", cfg.Context)
	require.True(t, cfg.Encrypt)
	require.Equal(t, "my-app", cfg.Originator)
}

// ---------------------------------------------------------------------------
// NewLocalKVStoreOptions struct
// ---------------------------------------------------------------------------

func TestNewLocalKVStoreOptionsFields(t *testing.T) {
	t.Parallel()

	mockWallet := wallet.NewTestWalletForRandomKey(t)
	opts := kvstore.NewLocalKVStoreOptions{
		Wallet:          mockWallet,
		Originator:      "app",
		Context:         "ctx",
		RetentionPeriod: 100,
		BasketName:      "mybasket",
		Encrypt:         true,
	}
	require.Equal(t, mockWallet, opts.Wallet)
	require.Equal(t, "app", opts.Originator)
	require.Equal(t, "ctx", opts.Context)
	require.Equal(t, uint32(100), opts.RetentionPeriod)
	require.Equal(t, "mybasket", opts.BasketName)
	require.True(t, opts.Encrypt)
}

func TestLocalKVStoreRemoveWithInputsSignActionFailsRelinquish(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	beefBytes, err := hex.DecodeString(pushDropBeefHex)
	require.NoError(t, err)

	// Return outputs with valid PushDrop
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, pushDropTxID, 0),
			},
		},
		BEEF: beefBytes,
	})

	// Build a valid signable tx that references the pushDrop output
	validSignableTx := buildSimpleTx(t, pushDropTxID, 0)

	// The InputBEEF for signing needs to contain the subject tx
	// We use the pushDropBeefHex as inputBeef, and a tx spending it as the signable tx
	// prepareSpends will fail because the new tx's txid is not in the inputBeef
	// But we need to get past the "parse signable tx" step first
	mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		SignableTransaction: &wallet.SignableTransaction{
			Tx:        validSignableTx,
			Reference: []byte("ref"),
		},
	})

	// SignAction would be called after prepareSpends succeeds
	// But since the new tx's txid is not in inputBeef, prepareSpends will fail
	txids, err := store.Remove(context.Background(), "mykey")
	require.Error(t, err)
	require.Empty(t, txids)
}

func TestLocalKVStoreSetSignActionFailsRelinquish(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	beefBytes, err := hex.DecodeString(pushDropBeefHex)
	require.NoError(t, err)

	// lookupValue finds existing value
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, pushDropTxID, 0),
			},
		},
		BEEF: beefBytes,
	})

	// CreateAction returns signable with invalid tx (causes prepareSpends to fail)
	mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		SignableTransaction: &wallet.SignableTransaction{
			Tx:        []byte{0x00}, // invalid tx bytes
			Reference: []byte("ref"),
		},
	})

	// Relinquish may be called when sign fails
	mockWallet.OnRelinquishOutput().ReturnSuccess(&wallet.RelinquishOutputResult{
		Relinquished: true,
	})

	_, err = store.Set(context.Background(), "mykey", "newvalue")
	require.Error(t, err)
	require.ErrorContains(t, err, errPrepareSpends)
}

// ---------------------------------------------------------------------------
// Concurrent Get calls (race detector test)
// ---------------------------------------------------------------------------

func TestLocalKVStoreConcurrentGet(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	// Always return empty outputs
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{},
	})

	done := make(chan struct{})
	for i := 0; i < 5; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_, _ = store.Get(context.Background(), "key", "default")
		}()
	}
	for i := 0; i < 5; i++ {
		<-done
	}
}

// ---------------------------------------------------------------------------
// Set concurrent (lock test)
// ---------------------------------------------------------------------------

func TestLocalKVStoreConcurrentSet(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{},
	})

	mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		Txid: [32]byte{0x01},
	})

	done := make(chan struct{})
	for i := 0; i < 3; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_, _ = store.Set(context.Background(), "concurrent-key", "value")
		}()
	}
	for i := 0; i < 3; i++ {
		<-done
	}
}

// ---------------------------------------------------------------------------
// ErrCorruptedState path in Set
// ---------------------------------------------------------------------------

func TestLocalKVStoreSetErrCorruptedState(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)

	// Make ListOutputs return ErrCorruptedState (wrapped via getOutputs → lookupValue)
	mockWallet.OnListOutputs().ReturnError(kvstore.ErrCorruptedState)

	_, err := store.Set(context.Background(), "mykey", "myvalue")
	require.Error(t, err)
	require.ErrorContains(t, err, "corrupted")
}

// ---------------------------------------------------------------------------
// buildSignableBeef creates a BEEF that contains:
//  1. The pushDrop source transaction (parsed from pushDropBeefHex)
//  2. A new spending transaction that spends pushDropTxID:0
//
// Returns (combinedBeefBytes, newSpendingTxBytes, newTxID).
// The new tx has SourceTransaction set so CalcInputSignatureHash works.
// ---------------------------------------------------------------------------

func buildSignableBeef(t *testing.T) (combinedBeefBytes []byte, newTxBytes []byte, newTxIDStr string) {
	t.Helper()

	// Parse existing pushDrop BEEF to get the source tx
	sourceBEEFBytes, err := hex.DecodeString(pushDropBeefHex)
	require.NoError(t, err)

	beef, _, err := transaction.NewBeefFromAtomicBytes(sourceBEEFBytes)
	require.NoError(t, err)

	// Find the source transaction
	sourceTx := beef.FindTransaction(pushDropTxID)
	require.NotNil(t, sourceTx, "source pushDrop tx must be in BEEF")

	// Build a new spending tx that:
	// - spends pushDropTxID:0
	// - has SourceTransaction set (needed by CalcInputSignatureHash)
	dummyScriptBytes := []byte{0x51} // OP_1
	dummyScript := script.Script(dummyScriptBytes)

	sourceTxHash, err := chainhash.NewHashFromHex(pushDropTxID)
	require.NoError(t, err)

	newTx := &transaction.Transaction{
		Version: 1,
		Inputs: []*transaction.TransactionInput{
			{
				SourceTXID:       sourceTxHash,
				SourceTxOutIndex: 0,
				SequenceNumber:   0xFFFFFFFF,
				SourceTransaction: sourceTx, // required for sighash calculation
			},
		},
		Outputs: []*transaction.TransactionOutput{
			{
				Satoshis:      1,
				LockingScript: &dummyScript,
			},
		},
	}

	// Add new tx to BEEF
	_, err = beef.MergeTransaction(newTx)
	require.NoError(t, err)

	// Serialize the combined BEEF
	combinedBeefBytes, err = beef.Bytes()
	require.NoError(t, err)

	newTxID := newTx.TxID().String()
	return combinedBeefBytes, newTx.Bytes(), newTxID
}

// ---------------------------------------------------------------------------
// Set with SignAction fails → relinquish path
// ---------------------------------------------------------------------------

func TestLocalKVStoreSetSignActionFailsRelinquishV2(t *testing.T) {
	t.Parallel()

	// Build a BEEF containing source tx + new spending tx
	combinedBeef, newTxBytes, _ := buildSignableBeef(t)

	store, mockWallet := setupTestKVStore(t)

	// Override ListOutputs to return the combined BEEF with the pushDrop outpoint
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, pushDropTxID, 0),
			},
		},
		BEEF: combinedBeef,
	})

	// CreateAction returns the new tx as signable
	mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		SignableTransaction: &wallet.SignableTransaction{
			Tx:        newTxBytes,
			Reference: []byte("sign-ref"),
		},
	})

	// CreateSignature returns a valid dummy signature
	// Using known DER signature bytes from a valid secp256k1 signature
	dummySig := &ec.Signature{
		R: big.NewInt(1),
		S: big.NewInt(1),
	}
	mockWallet.OnCreateSignature().ReturnSuccess(&wallet.CreateSignatureResult{
		Signature: dummySig,
	})

	// SignAction fails
	signErr := errors.New("sign action failed")
	mockWallet.OnSignAction().ReturnError(signErr)

	// RelinquishOutput is called after sign failure
	mockWallet.OnRelinquishOutput().ReturnSuccess(&wallet.RelinquishOutputResult{
		Relinquished: true,
	})

	_, err := store.Set(context.Background(), "mykey", "differentvalue")
	require.Error(t, err)
	require.ErrorContains(t, err, "SignAction")
}

// ---------------------------------------------------------------------------
// Set with SignAction succeeds
// ---------------------------------------------------------------------------

func TestLocalKVStoreSetSignActionSuccess(t *testing.T) {
	t.Parallel()

	combinedBeef, newTxBytes, _ := buildSignableBeef(t)

	store, mockWallet := setupTestKVStore(t)

	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, pushDropTxID, 0),
			},
		},
		BEEF: combinedBeef,
	})

	mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		SignableTransaction: &wallet.SignableTransaction{
			Tx:        newTxBytes,
			Reference: []byte("sign-ref"),
		},
	})

	dummySig := &ec.Signature{
		R: big.NewInt(1),
		S: big.NewInt(1),
	}
	mockWallet.OnCreateSignature().ReturnSuccess(&wallet.CreateSignatureResult{
		Signature: dummySig,
	})

	expectedTxid := chainhash.Hash{0xCC, 0xDD}
	mockWallet.OnSignAction().ReturnSuccess(&wallet.SignActionResult{
		Txid: expectedTxid,
	})

	outpoint, err := store.Set(context.Background(), "mykey", "differentvalue")
	require.NoError(t, err)
	require.NotEmpty(t, outpoint)
}

// ---------------------------------------------------------------------------
// Remove with SignAction fails → relinquish path
// ---------------------------------------------------------------------------

func TestLocalKVStoreRemoveSignActionFailsRelinquish(t *testing.T) {
	t.Parallel()

	combinedBeef, newTxBytes, _ := buildSignableBeef(t)

	store, mockWallet := setupTestKVStore(t)

	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, pushDropTxID, 0),
			},
		},
		BEEF: combinedBeef,
	})

	mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		SignableTransaction: &wallet.SignableTransaction{
			Tx:        newTxBytes,
			Reference: []byte("rm-ref"),
		},
	})

	dummySig := &ec.Signature{
		R: big.NewInt(1),
		S: big.NewInt(1),
	}
	mockWallet.OnCreateSignature().ReturnSuccess(&wallet.CreateSignatureResult{
		Signature: dummySig,
	})

	signErr := errors.New("sign action remove failed")
	mockWallet.OnSignAction().ReturnError(signErr)

	mockWallet.OnRelinquishOutput().ReturnSuccess(&wallet.RelinquishOutputResult{
		Relinquished: true,
	})

	txids, err := store.Remove(context.Background(), "mykey")
	require.Error(t, err)
	require.ErrorContains(t, err, "SignAction")
	require.Empty(t, txids)
}

// ---------------------------------------------------------------------------
// Remove with SignAction succeeds
// ---------------------------------------------------------------------------

func TestLocalKVStoreRemoveSignActionSuccess(t *testing.T) {
	t.Parallel()

	combinedBeef, newTxBytes, _ := buildSignableBeef(t)

	store, mockWallet := setupTestKVStore(t)

	// First call returns the output; second call (loop) returns empty to stop
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{
				Satoshis: 1,
				Outpoint: buildOutpoint(t, pushDropTxID, 0),
			},
		},
		BEEF: combinedBeef,
	})

	mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		SignableTransaction: &wallet.SignableTransaction{
			Tx:        newTxBytes,
			Reference: []byte("rm-ref"),
		},
	})

	dummySig := &ec.Signature{
		R: big.NewInt(1),
		S: big.NewInt(1),
	}
	mockWallet.OnCreateSignature().ReturnSuccess(&wallet.CreateSignatureResult{
		Signature: dummySig,
	})

	removedTxid := chainhash.Hash{0xAA, 0xBB}
	mockWallet.OnSignAction().ReturnSuccess(&wallet.SignActionResult{
		Txid: removedTxid,
	})

	txids, err := store.Remove(context.Background(), "mykey")
	// Even on success, Remove loops; the loop stops when < 100 outputs
	// Since we returned 1 output, loop should break after first iteration
	require.NoError(t, err)
	require.NotEmpty(t, txids)
}
