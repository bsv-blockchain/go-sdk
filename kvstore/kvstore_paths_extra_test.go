package kvstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/kvstore"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// TestLocalKVStoreGetEncryptedDecryptSuccess covers the successful-decrypt branch
// of lookupValue (local_kv_store.go:156), where an encrypted store decrypts the
// stored PushDrop field to obtain the plaintext value.
func TestLocalKVStoreGetEncryptedDecryptSuccess(t *testing.T) {
	t.Parallel()

	mockWallet := wallet.NewTestWalletForRandomKey(t)
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{Satoshis: 1, Outpoint: buildOutpoint(t, pushDropTxID, 0)},
		},
		BEEF: decodePushDropBeef(t),
	})
	mockWallet.OnDecrypt().ReturnSuccess(&wallet.DecryptResult{
		Plaintext: []byte("secret-value"),
	})

	store, err := kvstore.NewLocalKVStore(kvstore.KVStoreConfig{
		Wallet:  mockWallet,
		Context: "test-context",
		Encrypt: true,
	})
	require.NoError(t, err)

	value, err := store.Get(context.Background(), "mykey", "default")
	require.NoError(t, err)
	require.Equal(t, "secret-value", value)
}

// TestLocalKVStoreGetEncryptedDecryptError covers the decrypt-failure branch of
// lookupValue (local_kv_store.go:151-154).
func TestLocalKVStoreGetEncryptedDecryptError(t *testing.T) {
	t.Parallel()

	mockWallet := wallet.NewTestWalletForRandomKey(t)
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{
			{Satoshis: 1, Outpoint: buildOutpoint(t, pushDropTxID, 0)},
		},
		BEEF: decodePushDropBeef(t),
	})
	mockWallet.OnDecrypt().ReturnError(errors.New("decrypt boom"))

	store, err := kvstore.NewLocalKVStore(kvstore.KVStoreConfig{
		Wallet:  mockWallet,
		Context: "test-context",
		Encrypt: true,
	})
	require.NoError(t, err)

	_, err = store.Get(context.Background(), "mykey", "default")
	require.Error(t, err)
	require.ErrorContains(t, err, "decrypt boom")
}

// TestLocalKVStoreSetLockError covers the PushDrop.Lock failure branch of Set
// (local_kv_store.go:281-282). With no existing outputs, Set proceeds to build a
// new locking script; a failing GetPublicKey makes PushDrop.Lock error.
func TestLocalKVStoreSetLockError(t *testing.T) {
	t.Parallel()

	mockWallet := wallet.NewTestWalletForRandomKey(t)
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{},
	})
	mockWallet.OnGetPublicKey().ReturnError(errors.New("no pubkey available"))

	store, err := kvstore.NewLocalKVStore(kvstore.KVStoreConfig{
		Wallet:  mockWallet,
		Context: "test-context",
		Encrypt: false,
	})
	require.NoError(t, err)

	_, err = store.Set(context.Background(), "mykey", "myvalue")
	require.Error(t, err)
	require.ErrorContains(t, err, "locking script")
}

// TestLocalKVStoreSetEncryptError covers the encrypt-failure branch of Set
// (local_kv_store.go:259-261) for an encrypted store.
func TestLocalKVStoreSetEncryptError(t *testing.T) {
	t.Parallel()

	mockWallet := wallet.NewTestWalletForRandomKey(t)
	mockWallet.OnListOutputs().ReturnSuccess(&wallet.ListOutputsResult{
		Outputs: []wallet.Output{},
	})
	mockWallet.OnEncrypt().ReturnError(errors.New("encrypt boom"))

	store, err := kvstore.NewLocalKVStore(kvstore.KVStoreConfig{
		Wallet:  mockWallet,
		Context: "test-context",
		Encrypt: true,
	})
	require.NoError(t, err)

	_, err = store.Set(context.Background(), "mykey", "myvalue")
	require.Error(t, err)
	require.ErrorContains(t, err, "encrypt boom")
}

// TestLocalKVStoreSetPrepareSpendsSourceNotLinked covers the source-transaction
// linking guard in prepareSpends (local_kv_store.go:405-406). The signable tx is
// found within the input BEEF, but its input has no linked source transaction.
func TestLocalKVStoreSetPrepareSpendsSourceNotLinked(t *testing.T) {
	t.Parallel()

	store, mockWallet := setupTestKVStore(t)
	returnPushDropOutput(t, mockWallet)

	// Use the PushDrop transaction itself (present in the input BEEF) as the
	// signable transaction so FindTransactionForSigning locates it, then the
	// unlinked source transaction trips the linking guard.
	beefData, _, err := transaction.NewBeefFromAtomicBytes(decodePushDropBeef(t))
	require.NoError(t, err)
	pushTx := beefData.FindTransaction(pushDropTxID)
	require.NotNil(t, pushTx)

	mockWallet.OnCreateAction().ReturnSuccess(&wallet.CreateActionResult{
		SignableTransaction: &wallet.SignableTransaction{
			Tx:        pushTx.Bytes(),
			Reference: []byte("ref"),
		},
	})

	_, err = store.Set(context.Background(), "mykey", "differentvalue")
	require.Error(t, err)
	require.ErrorContains(t, err, errPrepareSpends)
}
