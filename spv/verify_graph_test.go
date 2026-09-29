package spv

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
)

// opTrue is a locking script any empty unlocking script satisfies.
var opTrue = script.NewFromBytes([]byte{script.Op1})

// minedCoins returns a transaction, the only one of a block at height 800,000,
// with an anyone-can-spend output of each amount.
func minedCoins(t *testing.T, amounts ...uint64) *transaction.Transaction {
	t.Helper()
	tx := transaction.NewTransaction()
	for _, sats := range amounts {
		tx.AddOutput(&transaction.TransactionOutput{Satoshis: sats, LockingScript: opTrue})
	}
	mp, err := transaction.NewMerklePathFromCoinbaseTxid(tx.TxID(), 800_000)
	require.NoError(t, err)
	tx.MerklePath = mp
	return tx
}

// coinRef names an output of a source transaction for spendCoins.
type coinRef struct {
	src  *transaction.Transaction
	vout uint32
}

// spendCoins returns a transaction spending each outpoint with an empty
// unlocking script and paying an anyone-can-spend output of each amount.
func spendCoins(spends []coinRef, amounts ...uint64) *transaction.Transaction {
	tx := transaction.NewTransaction()
	for _, op := range spends {
		tx.AddInputFromTx(op.src, op.vout, nil)
		tx.Inputs[len(tx.Inputs)-1].UnlockingScript = &script.Script{}
	}
	for _, sats := range amounts {
		tx.AddOutput(&transaction.TransactionOutput{Satoshis: sats, LockingScript: opTrue})
	}
	return tx
}

// blockHeaders is a mainnet ChainTracker that knows the merkle root of a few
// blocks and rejects every other root.
type blockHeaders map[uint32]chainhash.Hash

func (b blockHeaders) IsValidRootForHeight(_ context.Context, root *chainhash.Hash, height uint32) (bool, error) {
	known, ok := b[height]
	return ok && known.IsEqual(root), nil
}
func (blockHeaders) CurrentHeight(context.Context) (uint32, error) { return 967_896, nil }

// copyOf returns a separate Transaction with tx's content, and so its txid,
// carrying mp as its merkle path.
func copyOf(t *testing.T, tx *transaction.Transaction, mp *transaction.MerklePath) *transaction.Transaction {
	t.Helper()
	dup, err := transaction.NewTransactionFromBytes(tx.Bytes())
	require.NoError(t, err)
	require.True(t, dup.TxID().IsEqual(tx.TxID()))
	dup.MerklePath = mp
	return dup
}

// sourceCopies holds copies of a transaction with two P2SH outputs, whose
// redeem script is <pubkey> OP_CHECKSIG, mined at height 100, before
// Genesis, so the redeem script runs when they are spent.
type sourceCopies struct {
	priv   *ec.PrivateKey
	lock   *script.Script
	redeem *script.Script
	// src is the transaction without a merkle path.
	src *transaction.Transaction
	// honest is a copy of src with its height 100 merkle path.
	honest *transaction.Transaction
	// headers is a tracker that knows the merkle root of that block only.
	headers blockHeaders
}

func newSourceCopies(t *testing.T) *sourceCopies {
	t.Helper()
	priv, lock := spvKey(t)
	redeem := p2shRedeem(t, priv)
	src := transaction.NewTransaction()
	src.AddOutput(&transaction.TransactionOutput{Satoshis: 50_000, LockingScript: p2shOf(*redeem)})
	src.AddOutput(&transaction.TransactionOutput{Satoshis: 50_000, LockingScript: p2shOf(*redeem)})
	mp, err := transaction.NewMerklePathFromCoinbaseTxid(src.TxID(), 100)
	require.NoError(t, err)
	return &sourceCopies{
		priv:    priv,
		lock:    lock,
		redeem:  redeem,
		src:     src,
		honest:  copyOf(t, src, mp),
		headers: blockHeaders{100: *src.TxID()},
	}
}

// spend returns a transaction spending output 0 of first and output 1 of
// second, each a copy of c.src, signing only an input that spends c.honest.
func (c *sourceCopies) spend(t *testing.T, first, second *transaction.Transaction) *transaction.Transaction {
	t.Helper()
	tx := transaction.NewTransaction()
	tx.AddInputFromTx(first, 0, nil)
	tx.AddInputFromTx(second, 1, nil)
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 90_000, LockingScript: c.lock})
	unlockP2SH(t, tx, 0, c.priv, c.redeem, first == c.honest)
	unlockP2SH(t, tx, 1, c.priv, c.redeem, second == c.honest)
	return tx
}

// TestSPVVerifyDuplicateSourceCopies spends the outputs of sourceCopies
// through two Transaction values with its txid: the honest copy, whose output
// is spent with a signature, and a second copy, whose output is spent without
// one. The second copy must not make its output count as created after
// Genesis, whether it carries a merkle path forged for a post-Genesis height
// or no merkle path at all, and whichever input comes first.
func TestSPVVerifyDuplicateSourceCopies(t *testing.T) {
	c := newSourceCopies(t)
	forged, err := transaction.NewMerklePathFromCoinbaseTxid(c.src.TxID(), 700_000)
	require.NoError(t, err)

	// With both inputs signed the spend is valid.
	verified, err := Verify(t.Context(), c.spend(t, c.honest, c.honest), c.headers, nil)
	require.NoError(t, err)
	require.True(t, verified)

	for _, tc := range []struct {
		name    string
		copy    *transaction.Transaction
		tracker chaintracker.ChainTracker
		err     error
	}{
		// The chain tracker rejects the forged path.
		{"forged merkle path", copyOf(t, c.src, forged), c.headers, ErrInvalidMerklePath},
		// A tracker that accepts every root proves both heights, which
		// cannot both be the transaction's.
		{"forged merkle path, gullible tracker", copyOf(t, c.src, forged), &GullibleHeadersClient{}, ErrInvalidMerklePath},
		// The honest path proves the height of every copy's outputs.
		{"no merkle path", copyOf(t, c.src, nil), c.headers, ErrScriptVerificationFailed},
		{"no merkle path, gullible tracker", copyOf(t, c.src, nil), &GullibleHeadersClient{}, ErrScriptVerificationFailed},
	} {
		for _, copyFirst := range []bool{false, true} {
			tx := c.spend(t, c.honest, tc.copy)
			if copyFirst {
				tx = c.spend(t, tc.copy, c.honest)
			}
			verified, err := Verify(t.Context(), tx, tc.tracker, nil)
			require.ErrorIs(t, err, tc.err, "%s, copy first: %v", tc.name, copyFirst)
			require.False(t, verified, "%s, copy first: %v", tc.name, copyFirst)
		}
	}
}

// TestSPVVerifySourceTransactionMismatch checks that an input's source
// transaction must be the transaction its SourceTXID names: otherwise the
// output Verify checks the unlocking script against is not the one spent.
func TestSPVVerifySourceTransactionMismatch(t *testing.T) {
	_, lock := spvKey(t)
	named := minedSource(t, lock, 800_000)
	fake := minedCoins(t, 100_000)

	tx := transaction.NewTransaction()
	tx.AddInputFromTx(fake, 0, nil)
	tx.Inputs[0].UnlockingScript = &script.Script{}
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: lock})
	verified, err := Verify(t.Context(), tx, &GullibleHeadersClient{}, nil)
	require.NoError(t, err)
	require.True(t, verified)

	tx.Inputs[0].SourceTXID = named.TxID()
	verified, err = Verify(t.Context(), tx, &GullibleHeadersClient{}, nil)
	require.ErrorIs(t, err, ErrSourceTransactionMismatch)
	require.False(t, verified)

	// The same holds for an ancestor's input.
	child := transaction.NewTransaction()
	child.AddInputFromTx(tx, 0, nil)
	child.Inputs[0].UnlockingScript = &script.Script{}
	child.AddOutput(&transaction.TransactionOutput{Satoshis: 500, LockingScript: opTrue})
	verified, err = VerifyScripts(t.Context(), child)
	require.ErrorIs(t, err, ErrSourceTransactionMismatch)
	require.False(t, verified)
}

// TestSPVVerifyInputWithoutSourceTXID checks that an input that names no
// source transaction is reported rather than panicking while the spending
// transaction's txid is computed.
func TestSPVVerifyInputWithoutSourceTXID(t *testing.T) {
	src := minedCoins(t, 1000)
	tx := spendCoins([]coinRef{{src, 0}}, 900)
	tx.Inputs[0].SourceTXID = nil
	verified, err := Verify(t.Context(), tx, &GullibleHeadersClient{}, nil)
	require.ErrorIs(t, err, ErrMissingSourceTransaction)
	require.False(t, verified)
}

// TestSPVVerifySourceTransactionLacksOutput checks that an input whose source
// transaction has no output at its index is missing its source output, even
// when an output was supplied with SetSourceTxOutput.
func TestSPVVerifySourceTransactionLacksOutput(t *testing.T) {
	src := minedCoins(t, 1000)
	tx := spendCoins([]coinRef{{src, 0}}, 900)
	tx.Inputs[0].SourceTxOutIndex = 1
	tx.Inputs[0].SetSourceTxOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: opTrue})
	verified, err := Verify(t.Context(), tx, &GullibleHeadersClient{}, nil)
	require.ErrorIs(t, err, ErrMissingSourceTransaction)
	require.False(t, verified)
}

// TestSPVVerifyFanIn checks that a transaction spending 1,000 outputs of one
// large parent computes the parent's txid once rather than once per input:
// hashing the 4 MB parent per input would take seconds, once takes
// milliseconds, so the bound leaves room for slow runners.
func TestSPVVerifyFanIn(t *testing.T) {
	const inputs = 1000
	// A parent of about 4 MB: an output carrying 4 MB of data, then the
	// outputs the child spends.
	data := &script.Script{}
	require.NoError(t, data.AppendOpcodes(script.OpFALSE, script.OpRETURN))
	require.NoError(t, data.AppendPushData(bytes.Repeat([]byte{0x42}, 4_000_000)))
	for _, mined := range []bool{true, false} {
		parent := transaction.NewTransaction()
		if !mined {
			parent = spendCoins([]coinRef{{minedCoins(t, inputs), 0}})
		}
		parent.AddOutput(&transaction.TransactionOutput{LockingScript: data})
		for range inputs {
			parent.AddOutput(&transaction.TransactionOutput{Satoshis: 1, LockingScript: opTrue})
		}
		if mined {
			mp, err := transaction.NewMerklePathFromCoinbaseTxid(parent.TxID(), 800_000)
			require.NoError(t, err)
			parent.MerklePath = mp
		}
		// Built by hand: AddInputFromTx would hash the parent per input.
		parentTxid := parent.TxID()
		child := transaction.NewTransaction()
		for vout := range uint32(inputs) {
			child.AddInput(&transaction.TransactionInput{
				SourceTXID:        parentTxid,
				SourceTxOutIndex:  vout + 1,
				SourceTransaction: parent,
				UnlockingScript:   &script.Script{},
				SequenceNumber:    transaction.DefaultSequenceNumber,
			})
		}
		child.AddOutput(&transaction.TransactionOutput{Satoshis: inputs, LockingScript: opTrue})

		start := time.Now()
		verified, err := Verify(t.Context(), child, &GullibleHeadersClient{}, nil)
		elapsed := time.Since(start)
		require.NoError(t, err)
		require.True(t, verified)
		require.Less(t, elapsed, time.Second, "mined parent: %v", mined)
		t.Logf("mined parent %v: verified %d inputs in %v", mined, inputs, elapsed)
	}
}

// TestSPVVerifyStrippedProof presents a transaction that created P2SH
// outputs without its merkle path, so that it passes as unmined and its
// outputs would count as created after Chronicle, spendable with the redeem
// script alone. bitcoin-sv rejects any transaction that creates a P2SH output
// in a block after Genesis, so the unmined source must fail.
//
// Both spends of src are correctly signed, so that this fails on src's own
// P2SH-output-creation check rather than on the (also correct, since item
// A) requirement that an unproven, non-coinbase P2SH-shaped source be spent
// as a pre-Genesis coin.
func TestSPVVerifyStrippedProof(t *testing.T) {
	priv, lock := spvKey(t)
	redeem := p2shRedeem(t, priv)
	src := spendCoins([]coinRef{{minedCoins(t, 100_000), 0}}, 50_000, 50_000)
	for _, out := range src.Outputs {
		out.LockingScript = p2shOf(*redeem)
	}

	tx := transaction.NewTransaction()
	tx.AddInputFromTx(src, 0, nil)
	tx.AddInputFromTx(src, 1, nil)
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 90_000, LockingScript: lock})
	unlockP2SH(t, tx, 0, priv, redeem, true)
	unlockP2SH(t, tx, 1, priv, redeem, true)

	verified, err := Verify(t.Context(), tx, &GullibleHeadersClient{}, nil)
	require.ErrorIs(t, err, ErrP2SHOutput)
	require.False(t, verified)
}
