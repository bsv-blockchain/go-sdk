package transaction

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Merging the same transaction twice must be a no-op, and merging a tip whose
// ancestry is a DAG must still pull in every distinct ancestor exactly once —
// the skip that keeps that walk from going exponential must not drop anything.

func TestMergeTransactionSpendGraphKeepsEveryAncestor(t *testing.T) {
	txs := benchSpendGraph(12)
	tip := txs[len(txs)-1]

	beef := NewBeef()
	_, err := beef.MergeTransaction(tip)
	require.NoError(t, err)

	require.Len(t, beef.Transactions, len(txs), "every distinct ancestor should be merged")
	for i, tx := range txs {
		stored, ok := beef.Transactions[*tx.TxID()]
		require.Truef(t, ok, "ancestor %d missing from merged BEEF", i)
		require.NotNil(t, stored.Transaction)
		assert.Equal(t, RawTx, stored.DataFormat)
	}
}

func TestMergeTransactionIsIdempotent(t *testing.T) {
	txs := benchSpendGraph(8)
	tip := txs[len(txs)-1]

	beef := NewBeef()
	_, err := beef.MergeTransaction(tip)
	require.NoError(t, err)
	first, err := beef.Bytes()
	require.NoError(t, err)

	// Merge the tip again, then every ancestor in turn.
	_, err = beef.MergeTransaction(tip)
	require.NoError(t, err)
	for _, tx := range txs {
		_, err = beef.MergeTransaction(tx)
		require.NoError(t, err)
	}

	second, err := beef.Bytes()
	require.NoError(t, err)
	assert.Equal(t, first, second, "re-merging known transactions must not change the graph")
}

func TestMergeTransactionUpgradesUnprovedToProved(t *testing.T) {
	// One block of four transactions, each with its own proof.
	proved := benchProvedBatch(4, 1)
	tx := proved[0]
	proof := tx.MerklePath
	require.NotNil(t, proof)

	// Merge it first without the proof...
	tx.MerklePath = nil
	beef := NewBeef()
	stored, err := beef.MergeTransaction(tx)
	require.NoError(t, err)
	require.Equal(t, RawTx, stored.DataFormat)
	require.Empty(t, beef.BUMPs)

	// ...then again with it. The stored entry must pick the proof up.
	tx.MerklePath = proof
	stored, err = beef.MergeTransaction(tx)
	require.NoError(t, err)
	assert.Equal(t, RawTxAndBumpIndex, stored.DataFormat)
	assert.Len(t, beef.BUMPs, 1)
	assert.Equal(t, beef.BUMPs[0].BlockHeight, proof.BlockHeight)
}

func TestMergeTransactionDoesNotDowngradeProved(t *testing.T) {
	proved := benchProvedBatch(4, 1)
	tx := proved[0]
	proof := tx.MerklePath

	beef := NewBeef()
	stored, err := beef.MergeTransaction(tx)
	require.NoError(t, err)
	require.Equal(t, RawTxAndBumpIndex, stored.DataFormat)

	// A copy arriving without a proof must not clear the one already held.
	unproved := *tx
	unproved.MerklePath = nil
	stored, err = beef.MergeTransaction(&unproved)
	require.NoError(t, err)
	assert.Equal(t, RawTxAndBumpIndex, stored.DataFormat)
	assert.Equal(t, proof, stored.Transaction.MerklePath)
}

func TestMergeTransactionUpgradesTxidOnlyAncestor(t *testing.T) {
	txs := benchSpendGraph(6)
	tip := txs[len(txs)-1]
	ancestor := txs[0]

	// Seed the ancestor as a bare txid, then merge the tip over it.
	beef := NewBeef()
	beef.MergeTxidOnly(ancestor.TxID())
	require.Equal(t, TxIDOnly, beef.Transactions[*ancestor.TxID()].DataFormat)

	_, err := beef.MergeTransaction(tip)
	require.NoError(t, err)

	stored := beef.Transactions[*ancestor.TxID()]
	require.NotNil(t, stored.Transaction)
	assert.Equal(t, RawTx, stored.DataFormat, "a txid-only entry must be upgraded to the raw transaction")
}

func TestMergeTransactionKeysParentsByTheirOwnTxid(t *testing.T) {
	// An input's SourceTXID is caller-supplied metadata and can disagree with
	// the transaction actually linked as SourceTransaction. Keying the parent by
	// SourceTXID in that case files one transaction under two txids, and Bytes()
	// then announces the map size while writing the smaller deduplicated set —
	// a BEEF that fails to decode.
	realParent := benchTx(1)
	child := benchTx(2, realParent)

	// Point the input at some other txid while still linking the real parent.
	imposter := benchTx(99).TxID()
	child.Inputs[0].SourceTXID = imposter

	beef := NewBeef()
	_, err := beef.MergeTransaction(child)
	require.NoError(t, err)

	for txid, btx := range beef.Transactions {
		if btx.DataFormat == TxIDOnly || btx.Transaction == nil {
			continue
		}
		require.Equalf(t, txid.String(), btx.Transaction.TxID().String(),
			"transaction stored under a txid that is not its own")
	}

	raw, err := beef.Bytes()
	require.NoError(t, err)

	parsed, err := NewBeefFromBytes(raw)
	require.NoError(t, err, "serialized BEEF must decode")
	assert.Len(t, parsed.Transactions, len(beef.Transactions),
		"every announced transaction must survive the round trip")
}

func TestFindAtomicTransactionLinksWholeAncestry(t *testing.T) {
	// Skipping already-visited nodes must not leave source links unset: every
	// input reachable from the tip should end up pointing at its parent.
	txs := benchSpendGraph(10)
	tip := txs[len(txs)-1]

	beef := beefOf(txs)
	resolved := beef.FindAtomicTransactionByHash(tip.TxID())
	require.NotNil(t, resolved)

	byTxid := make(map[string]*Transaction, len(txs))
	for _, tx := range txs {
		byTxid[tx.TxID().String()] = tx
	}

	var check func(tx *Transaction, depth int)
	seen := make(map[string]bool)
	check = func(tx *Transaction, depth int) {
		id := tx.TxID().String()
		if seen[id] || depth > len(txs) {
			return
		}
		seen[id] = true
		for _, in := range tx.Inputs {
			require.NotNilf(t, in.SourceTransaction, "input of %s has no linked source transaction", id)
			require.Equal(t, in.SourceTXID.String(), in.SourceTransaction.TxID().String(),
				"linked source transaction must match the input's SourceTXID")
			check(in.SourceTransaction, depth+1)
		}
	}
	check(resolved, 0)

	require.Len(t, seen, len(txs), "every ancestor should be reachable through the linked graph")
}

func TestFindAtomicTransactionStopsAtProvenAncestor(t *testing.T) {
	// A transaction with a proof is terminal: its own ancestry is not walked.
	proved := benchProvedBatch(4, 1)
	parent := proved[0]

	child := benchTx(4242, parent)
	beef := NewBeef()
	_, err := beef.MergeTransaction(child)
	require.NoError(t, err)

	resolved := beef.FindAtomicTransactionByHash(child.TxID())
	require.NotNil(t, resolved)
	require.Len(t, resolved.Inputs, 1)

	source := resolved.Inputs[0].SourceTransaction
	require.NotNil(t, source)
	assert.NotNil(t, source.MerklePath, "a proven ancestor should carry its proof")
}

func TestMergeTransactionMergesAncestorsMissingFromPartialGraph(t *testing.T) {
	// A copy already in the graph may have been merged without its source
	// links; a later copy that has them must still contribute the ancestry.
	txs := benchSpendGraph(6)
	tip := txs[len(txs)-1]

	stripped := *tip
	stripped.Inputs = make([]*TransactionInput, 0, len(tip.Inputs))
	for _, in := range tip.Inputs {
		cp := *in
		cp.SourceTransaction = nil
		stripped.Inputs = append(stripped.Inputs, &cp)
	}

	beef := NewBeef()
	_, err := beef.MergeTransaction(&stripped)
	require.NoError(t, err)
	require.Len(t, beef.Transactions, 1, "stripped copy carries no ancestry")

	_, err = beef.MergeTransaction(tip)
	require.NoError(t, err)
	assert.Len(t, beef.Transactions, len(txs), "the full copy must contribute the ancestry")
}
