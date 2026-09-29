package spv

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// TestVerifyDiamondChainVerifiesEachTxOnce builds a chain of unmined
// diamonds (a transaction with two outputs, each spent by its own
// transaction, both of which are spent by the next one). Verify must check
// every transaction once rather than once per path to it, which would take
// 2^k script verifications for k diamonds.
func TestVerifyDiamondChainVerifiesEachTxOnce(t *testing.T) {
	const diamonds = 40
	lock := script.NewFromBytes([]byte{script.Op1})
	unlock := script.NewFromBytes([]byte{script.Op1})
	outputs := func(n int) []*transaction.TransactionOutput {
		outs := make([]*transaction.TransactionOutput, n)
		for i := range outs {
			outs[i] = &transaction.TransactionOutput{LockingScript: lock, Satoshis: 1}
		}
		return outs
	}
	spend := func(src *transaction.Transaction, vout uint32) *transaction.TransactionInput {
		return &transaction.TransactionInput{
			SourceTXID:        src.TxID(),
			SourceTxOutIndex:  vout,
			SourceTransaction: src,
			UnlockingScript:   unlock,
			SequenceNumber:    0xffffffff,
		}
	}

	// The first transaction spends an output supplied without its source.
	first := &transaction.Transaction{Version: 1, Outputs: outputs(2)}
	in := &transaction.TransactionInput{
		SourceTXID:      &chainhash.Hash{},
		UnlockingScript: unlock,
		SequenceNumber:  0xffffffff,
	}
	in.SetSourceTxOutput(&transaction.TransactionOutput{LockingScript: lock, Satoshis: 2})
	first.Inputs = []*transaction.TransactionInput{in}

	top := first
	for range diamonds {
		left := &transaction.Transaction{Version: 1, Inputs: []*transaction.TransactionInput{spend(top, 0)}, Outputs: outputs(1)}
		right := &transaction.Transaction{Version: 1, Inputs: []*transaction.TransactionInput{spend(top, 1)}, Outputs: outputs(1)}
		top = &transaction.Transaction{
			Version: 1,
			Inputs:  []*transaction.TransactionInput{spend(left, 0), spend(right, 0)},
			Outputs: outputs(2),
		}
	}

	start := time.Now()
	verified, err := VerifyScripts(t.Context(), top)
	require.NoError(t, err)
	require.True(t, verified)
	require.Less(t, time.Since(start), 10*time.Second)
}
