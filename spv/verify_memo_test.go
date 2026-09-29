package spv

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
)

// countingTracker wraps a ChainTracker and counts calls reaching it, to
// check that memoTracker (Verify's own wrapping) asks it at most once per
// distinct question.
type countingTracker struct {
	chaintracker.ChainTracker

	rootCalls   int
	heightCalls int
}

func (c *countingTracker) IsValidRootForHeight(ctx context.Context, root *chainhash.Hash, height uint32) (bool, error) {
	c.rootCalls++
	return c.ChainTracker.IsValidRootForHeight(ctx, root, height)
}

func (c *countingTracker) CurrentHeight(ctx context.Context) (uint32, error) {
	c.heightCalls++
	return c.ChainTracker.CurrentHeight(ctx)
}

// twoTxBlock returns two transactions, each the only difference being their
// own output, both proven mined at height by the same two-leaf merkle path,
// so both compute the same root.
func twoTxBlock(height uint32) (a, b *transaction.Transaction) {
	a = transaction.NewTransaction()
	a.AddOutput(&transaction.TransactionOutput{Satoshis: 1, LockingScript: opTrue})
	b = transaction.NewTransaction()
	b.AddOutput(&transaction.TransactionOutput{Satoshis: 2, LockingScript: opTrue})
	isTxid := true
	path := [][]*transaction.PathElement{{
		{Offset: 0, Hash: a.TxID(), Txid: &isTxid},
		{Offset: 1, Hash: b.TxID(), Txid: &isTxid},
	}}
	a.MerklePath = &transaction.MerklePath{BlockHeight: height, Path: path}
	b.MerklePath = &transaction.MerklePath{BlockHeight: height, Path: path}
	return a, b
}

// TestSPVVerifyMemoizesChainTracker checks that Verify asks its chain
// tracker at most once for each distinct (root, height) pair, however many
// times the graph reaches it: N parsed copies of one mined parent, or
// several transactions from one block, still cause one
// IsValidRootForHeight call.
func TestSPVVerifyMemoizesChainTracker(t *testing.T) {
	const copies = 5
	const height = 800_000
	parent := minedCoins(t, 1, 1, 1, 1, 1)
	tracker := &countingTracker{ChainTracker: blockHeaders{height: *parent.TxID()}}

	child := transaction.NewTransaction()
	for i := range uint32(copies) {
		cp := copyOf(t, parent, parent.MerklePath)
		child.AddInput(&transaction.TransactionInput{
			SourceTXID:        cp.TxID(),
			SourceTxOutIndex:  i,
			SourceTransaction: cp,
			UnlockingScript:   &script.Script{},
			SequenceNumber:    transaction.DefaultSequenceNumber,
		})
	}
	child.AddOutput(&transaction.TransactionOutput{Satoshis: 1, LockingScript: opTrue})

	verified, err := Verify(t.Context(), child, tracker, nil)
	require.NoError(t, err)
	require.True(t, verified)
	require.Equal(t, 1, tracker.rootCalls, "%d copies of one mined parent must cause one IsValidRootForHeight call", copies)

	// Two distinct transactions mined in the same block (same root and
	// height) also share the memoized answer.
	a, b := twoTxBlock(height + 1)
	root, err := a.MerklePath.ComputeRoot(a.TxID())
	require.NoError(t, err)
	tracker2 := &countingTracker{ChainTracker: blockHeaders{height + 1: *root}}

	child2 := transaction.NewTransaction()
	child2.AddInputFromTx(a, 0, nil)
	child2.Inputs[0].UnlockingScript = &script.Script{}
	child2.AddInputFromTx(b, 0, nil)
	child2.Inputs[1].UnlockingScript = &script.Script{}
	child2.AddOutput(&transaction.TransactionOutput{Satoshis: 1, LockingScript: opTrue})

	verified, err = Verify(t.Context(), child2, tracker2, nil)
	require.NoError(t, err)
	require.True(t, verified)
	require.Equal(t, 1, tracker2.rootCalls, "two transactions from one block must cause one IsValidRootForHeight call")
}

// TestSPVVerifyMemoTrackerActivationHeights checks that memoTracker still
// lets Verify read the caller's tracker's activation heights: memoTracker
// itself does not implement ActivationHeightsProvider, so Verify must read
// them before wrapping, not after.
func TestSPVVerifyMemoTrackerActivationHeights(t *testing.T) {
	testnet := WithActivationHeights(&GullibleHeadersClient{}, scriptflag.TestNetActivationHeights)
	unsigned := p2shSpend(t, 700_000, false)
	verified, err := Verify(t.Context(), unsigned, testnet, nil)
	require.ErrorIs(t, err, ErrScriptVerificationFailed)
	require.False(t, verified)
}
