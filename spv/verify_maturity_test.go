package spv

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
)

// coinbaseSpend returns a transaction spending output 0 of a coinbase-shaped
// source mined at height, or, when mined is false, an otherwise identical
// coinbase-shaped source with no merkle path at all.
func coinbaseSpend(t *testing.T, height uint32, mined bool) *transaction.Transaction {
	t.Helper()
	src := coinbaseSource(t, opTrue, height)
	if !mined {
		src.MerklePath = nil
	}
	tx := transaction.NewTransaction()
	tx.AddInputFromTx(src, 0, nil)
	tx.Inputs[0].UnlockingScript = &script.Script{}
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: opTrue})
	return tx
}

// TestSPVVerifyCoinbaseMaturity checks Consensus::CheckTxInputs' coinbase
// maturity rule (validation.cpp:2617-2625, COINBASE_MATURITY 100).
func TestSPVVerifyCoinbaseMaturity(t *testing.T) {
	const tip = 700_000
	tracker := tipTracker(tip)

	// An unproven coinbase source (no merkle path) is premature: its depth
	// cannot be known.
	verified, err := Verify(t.Context(), coinbaseSpend(t, 0, false), tracker, nil)
	require.ErrorIs(t, err, ErrPrematureCoinbaseSpend)
	require.False(t, verified)

	// Proven mined, but one block short of coinbaseMaturity deep.
	verified, err = Verify(t.Context(), coinbaseSpend(t, tip-coinbaseMaturity+2, true), tracker, nil)
	require.ErrorIs(t, err, ErrPrematureCoinbaseSpend)
	require.False(t, verified)

	// Exactly coinbaseMaturity blocks deep: mature.
	verified, err = Verify(t.Context(), coinbaseSpend(t, tip-coinbaseMaturity+1, true), tracker, nil)
	require.NoError(t, err)
	require.True(t, verified)
}

// TestSPVVerifyUnminedCoinbase checks that a transaction that is itself
// coinbase-shaped (one input spending the null outpoint) and has no merkle
// path is rejected: CheckRegularTransaction rejects every coinbase
// (validation.cpp:604-609), so it could only be valid as a block's first
// transaction, which Verify never reaches for an unmined transaction.
func TestSPVVerifyUnminedCoinbase(t *testing.T) {
	cb := coinbaseSource(t, opTrue, 0)
	cb.MerklePath = nil
	verified, err := Verify(t.Context(), cb, &GullibleHeadersClient{}, nil)
	require.ErrorIs(t, err, ErrUnminedCoinbase)
	require.False(t, verified)
}

// TestSPVVerifyEFInputCoinbaseMaturityTrusted checks that an Extended Format
// input, which carries no SourceTransaction, is not checked for coinbase
// maturity: Verify cannot know it spends a coinbase output at all, so this
// is trusted along with the rest of what an EF input supplies (see Verify's
// doc comment). unminedSource builds exactly such an input.
func TestSPVVerifyEFInputCoinbaseMaturityTrusted(t *testing.T) {
	tx := transaction.NewTransaction()
	src := unminedSource(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: opTrue})
	tx.AddInputFromTx(src, 0, nil)
	tx.Inputs[0].UnlockingScript = &script.Script{}
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: opTrue})

	// src's own input carries no SourceTransaction (that is what
	// unminedSource builds): even under a chain tip of 0, where a real
	// coinbase spend would always be premature, Verify has no way to know
	// src's input spends a coinbase at all, so it is trusted.
	verified, err := Verify(t.Context(), tx, tipTracker(0), nil)
	require.NoError(t, err)
	require.True(t, verified)
}

// TestSPVVerifyScriptsSkipsCoinbaseMaturity checks that VerifyScripts, which
// has no real chain tip, skips the coinbase-maturity check rather than
// judging maturity against a dummy height.
func TestSPVVerifyScriptsSkipsCoinbaseMaturity(t *testing.T) {
	// Mined at height 0 and never proven any depth beyond that: premature
	// under any real chain tip, but VerifyScripts does not consult one.
	verified, err := VerifyScripts(t.Context(), coinbaseSpend(t, 0, true))
	require.NoError(t, err)
	require.True(t, verified)
}

// TestSPVVerifyGullibleHeadersClientSkipsCoinbaseMaturity checks that Verify
// with &GullibleHeadersClient{}, as docs/examples/verify_transaction uses it,
// skips coinbase maturity as VerifyScripts does rather than judging it
// against GullibleHeadersClient's placeholder CurrentHeight of 800,000.
func TestSPVVerifyGullibleHeadersClientSkipsCoinbaseMaturity(t *testing.T) {
	for _, tracker := range []chaintracker.ChainTracker{
		&GullibleHeadersClient{},
		WithActivationHeights(&GullibleHeadersClient{}, scriptflag.MainNetActivationHeights),
	} {
		verified, err := Verify(t.Context(), coinbaseSpend(t, 799_950, true), tracker, nil)
		require.NoError(t, err)
		require.True(t, verified)
	}
}
