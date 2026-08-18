package transaction

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A TxIDOnly entry carries a txid and no transaction: that is the shape
// MergeTxidOnly builds, and what ValidateTransactions, String and the writer all
// read. The reader has to produce the same shape, or a round trip through the
// wire format turns a bare txid into a bare txid PLUS an empty transaction -
// which then gets linked into whatever spends it, panics SourceTxOutput, and
// merges into other graphs as a transaction of its own.

func TestNewBeefFromBytesLeavesNoTransactionOnATxIDOnlyEntry(t *testing.T) {
	parent := benchTx(0)
	child := benchTx(1, parent)

	beef := NewBeefV2()
	_, err := beef.MergeRawTx(child.Bytes(), nil)
	require.NoError(t, err)
	beef.MergeTxidOnly(parent.TxID())

	raw, err := beef.Bytes()
	require.NoError(t, err)

	parsed, err := NewBeefFromBytes(raw)
	require.NoError(t, err)

	parentEntry := parsed.Transactions[*parent.TxID()]
	require.NotNil(t, parentEntry)
	assert.Equal(t, TxIDOnly, parentEntry.DataFormat)
	assert.Nil(t, parentEntry.Transaction, "a bare txid must not come back with a transaction attached")
	require.NotNil(t, parentEntry.KnownTxID)
	assert.Equal(t, *parent.TxID(), *parentEntry.KnownTxID)

	childEntry := parsed.Transactions[*child.TxID()]
	require.NotNil(t, childEntry)
	require.NotNil(t, childEntry.Transaction)
	require.Len(t, childEntry.Transaction.Inputs, 1)
	assert.Nil(t, childEntry.Transaction.Inputs[0].SourceTransaction,
		"an input whose source is a bare txid must not be linked to a transaction it cannot spend")
}

// Merging a parsed graph must not smuggle a placeholder in as an entry of its
// own: MergeTransaction follows SourceTransaction pointers, so a linked
// placeholder used to land in the target graph under the txid of an empty
// transaction.
func TestMergeBeefDoesNotIntroduceAPlaceholderForATxIDOnlyEntry(t *testing.T) {
	parent := benchTx(0)
	child := benchTx(1, parent)

	source := NewBeefV2()
	_, err := source.MergeRawTx(child.Bytes(), nil)
	require.NoError(t, err)
	source.MergeTxidOnly(parent.TxID())

	raw, err := source.Bytes()
	require.NoError(t, err)

	parsed, err := NewBeefFromBytes(raw)
	require.NoError(t, err)

	target := NewBeefV2()
	require.NoError(t, target.MergeBeef(parsed))

	emptyTxID := (&Transaction{}).TxID()
	assert.NotContains(t, target.Transactions, *emptyTxID,
		"the empty-transaction txid must never appear in a merged graph")

	for txid, entry := range target.Transactions {
		if entry.DataFormat == TxIDOnly {
			continue
		}
		require.NotNilf(t, entry.Transaction, "entry %s has no transaction", txid)
		assert.Falsef(t, len(entry.Transaction.Inputs) == 0 && len(entry.Transaction.Outputs) == 0,
			"entry %s is an empty transaction", txid)
	}
}

// SourceTxOutput used to index Outputs unchecked, so any input linked to a
// transaction that does not carry the output it spends panicked.
func TestSourceTxOutputDoesNotPanicWhenTheSourceLacksTheOutput(t *testing.T) {
	input := &TransactionInput{
		SourceTransaction: &Transaction{},
		SourceTxOutIndex:  0,
	}

	assert.NotPanics(t, func() {
		assert.Nil(t, input.SourceTxOutput())
		assert.Nil(t, input.SourceTxScript())
	})
}
