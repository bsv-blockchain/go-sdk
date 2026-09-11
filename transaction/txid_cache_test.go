package transaction_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// TestSetTxHash verifies TxID returns the caller-set cache and that clearing it
// with nil restores computation of the real transaction id.
func TestSetTxHash(t *testing.T) {
	tx := benchP2PKHTx(t, 2)
	realID := *tx.TxID()

	// A bogus cached hash proves TxID consults the cache rather than recomputing.
	var bogus chainhash.Hash
	bogus[0], bogus[31] = 0xAB, 0xCD
	tx.SetTxHash(&bogus)
	require.Equal(t, bogus, *tx.TxID())

	// Clearing the cache restores the real id.
	tx.SetTxHash(nil)
	require.Equal(t, realID, *tx.TxID())
}

// TestTxIDNotAutoCached verifies TxID never populates the cache itself, so a
// mutation after a plain read is reflected (there is no hidden, stale cache).
func TestTxIDNotAutoCached(t *testing.T) {
	tx := benchP2PKHTx(t, 1)
	before := *tx.TxID()
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 5, LockingScript: tx.Outputs[0].LockingScript})
	require.NotEqual(t, before, *tx.TxID(), "TxID must reflect mutations when no hash was set")
}

// TestTxIDCachedZeroAlloc confirms a cached TxID returns without allocating.
func TestTxIDCachedZeroAlloc(t *testing.T) {
	tx := benchP2PKHTx(t, 16)
	tx.SetTxHash(tx.TxID())
	allocs := testing.AllocsPerRun(200, func() {
		_ = tx.TxID()
	})
	require.Zero(t, allocs, "cached TxID must not allocate")
}

// BenchmarkTxIDCached measures TxID with a set cache; contrast with
// BenchmarkTxID, which re-serializes and double-hashes on every call.
func BenchmarkTxIDCached(b *testing.B) {
	for _, nIn := range []int{1, 16, 64} {
		b.Run(fmt.Sprintf("inputs=%d", nIn), func(b *testing.B) {
			tx := benchP2PKHTx(b, nIn)
			tx.SetTxHash(tx.TxID())
			b.ReportAllocs()
			for b.Loop() {
				_ = tx.TxID()
			}
		})
	}
}
