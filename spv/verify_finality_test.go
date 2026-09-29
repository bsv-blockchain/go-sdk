package spv

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
)

// tipTracker is a ChainTracker that confirms any merkle root and reports a
// fixed CurrentHeight.
type tipTracker uint32

func (tr tipTracker) IsValidRootForHeight(context.Context, *chainhash.Hash, uint32) (bool, error) {
	return true, nil
}
func (tr tipTracker) CurrentHeight(context.Context) (uint32, error) { return uint32(tr), nil }

// erroringHeight is a ChainTracker that confirms any merkle root but fails
// CurrentHeight, to prove a check never needed the chain tip.
type erroringHeight struct{}

func (erroringHeight) IsValidRootForHeight(context.Context, *chainhash.Hash, uint32) (bool, error) {
	return true, nil
}

func (erroringHeight) CurrentHeight(context.Context) (uint32, error) {
	return 0, errors.New("CurrentHeight must not be called")
}

// finalityTx returns an unmined transaction, with the given nLockTime,
// spending an anyone-can-spend EF-style output with the given sequence
// number on its only input.
func finalityTx(lockTime, sequence uint32) *transaction.Transaction {
	src := unminedSource(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: opTrue})
	tx := transaction.NewTransaction()
	tx.LockTime = lockTime
	tx.AddInputFromTx(src, 0, nil)
	tx.Inputs[0].UnlockingScript = &script.Script{}
	tx.Inputs[0].SequenceNumber = sequence
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: opTrue})
	return tx
}

// TestSPVVerifyFinality checks verifyTx's IsFinalTx equivalent
// (validation.cpp:228-248): a non-final input matters only once nLockTime is
// set, and then only up to the block tx would be mined in next.
func TestSPVVerifyFinality(t *testing.T) {
	const tip = 700_000
	tracker := tipTracker(tip)

	// A non-final input with a height-based nLockTime at or beyond tip+1
	// (the block tx would be mined in) is not yet final.
	verified, err := Verify(t.Context(), finalityTx(tip+1, 0), tracker, nil)
	require.ErrorIs(t, err, ErrNonFinalTransaction)
	require.False(t, verified)

	// The same nLockTime, one block earlier, has already passed.
	verified, err = Verify(t.Context(), finalityTx(tip, 0), tracker, nil)
	require.NoError(t, err)
	require.True(t, verified)

	// A non-final input with a time-based nLockTime (at or above
	// LOCKTIME_THRESHOLD) cannot be resolved without the chain tip's
	// median time past, which chaintracker.ChainTracker cannot report, so
	// it is rejected rather than guessed at.
	verified, err = Verify(t.Context(), finalityTx(lockTimeThreshold, 0), tracker, nil)
	require.ErrorIs(t, err, ErrNonFinalTransaction)
	require.False(t, verified)

	// Every input sequence-final: tx is final regardless of nLockTime, and
	// the chain tip is never consulted.
	verified, err = Verify(t.Context(), finalityTx(lockTimeThreshold, transaction.DefaultSequenceNumber), erroringHeight{}, nil)
	require.NoError(t, err)
	require.True(t, verified)

	// No nLockTime: tx is final regardless of sequence numbers, and the
	// chain tip is never consulted.
	verified, err = Verify(t.Context(), finalityTx(0, 0), erroringHeight{}, nil)
	require.NoError(t, err)
	require.True(t, verified)
}

// TestSPVVerifyScriptsSkipsFinality checks that VerifyScripts, which has no
// real chain tip (GullibleHeadersClient.CurrentHeight is a dummy value),
// skips the finality check rather than judging finality against it.
func TestSPVVerifyScriptsSkipsFinality(t *testing.T) {
	verified, err := VerifyScripts(t.Context(), finalityTx(unminedHeight, 0))
	require.NoError(t, err)
	require.True(t, verified)
}

// TestSPVVerifyGullibleHeadersClientSkipsFinality checks that Verify with
// &GullibleHeadersClient{}, as docs/examples/verify_transaction uses it,
// skips finality as VerifyScripts does rather than judging an
// anti-fee-sniping nLockTime against GullibleHeadersClient's placeholder
// CurrentHeight of 800,000, also when the client is wrapped by
// WithActivationHeights.
func TestSPVVerifyGullibleHeadersClientSkipsFinality(t *testing.T) {
	for _, tracker := range []chaintracker.ChainTracker{
		&GullibleHeadersClient{},
		WithActivationHeights(&GullibleHeadersClient{}, scriptflag.TestNetActivationHeights),
	} {
		verified, err := Verify(t.Context(), finalityTx(900_000, 0), tracker, nil)
		require.NoError(t, err)
		require.True(t, verified)
	}
}

// TestSPVVerifyFinalityTipOverflow checks that a tracker reporting
// math.MaxUint32 as its height does not wrap tip+1 to 0 and make every
// height-locked transaction non-final.
func TestSPVVerifyFinalityTipOverflow(t *testing.T) {
	verified, err := Verify(t.Context(), finalityTx(1, 0), tipTracker(math.MaxUint32), nil)
	require.NoError(t, err)
	require.True(t, verified)
}

// medianTimeTracker is a ChainTracker that also implements
// MedianTimePastProvider, reporting a fixed CurrentHeight and a fixed
// median time past.
type medianTimeTracker struct {
	tip uint32
	mtp uint32
}

func (tr medianTimeTracker) IsValidRootForHeight(context.Context, *chainhash.Hash, uint32) (bool, error) {
	return true, nil
}
func (tr medianTimeTracker) CurrentHeight(context.Context) (uint32, error) { return tr.tip, nil }
func (tr medianTimeTracker) MedianTimePast(context.Context) (uint32, error) {
	return tr.mtp, nil
}

// TestSPVVerifyFinalityMedianTimePast checks that a chain tracker that
// implements MedianTimePastProvider, directly or wrapped by
// WithActivationHeights, lets Verify resolve a non-final input under a
// time-based nLockTime instead of always rejecting it.
func TestSPVVerifyFinalityMedianTimePast(t *testing.T) {
	const lockTime = 1_600_000_000 // 2020-09-13, well above lockTimeThreshold
	tracker := medianTimeTracker{tip: 967_896, mtp: lockTime + 1}

	// nLockTime has passed median time past: final.
	verified, err := Verify(t.Context(), finalityTx(lockTime, 0), tracker, nil)
	require.NoError(t, err)
	require.True(t, verified)

	// The same through WithActivationHeights.
	verified, err = Verify(t.Context(), finalityTx(lockTime, 0), WithActivationHeights(tracker, scriptflag.MainNetActivationHeights), nil)
	require.NoError(t, err)
	require.True(t, verified)

	// nLockTime has not yet passed median time past: not final.
	tracker.mtp = lockTime
	verified, err = Verify(t.Context(), finalityTx(lockTime, 0), tracker, nil)
	require.ErrorIs(t, err, ErrNonFinalTransaction)
	require.False(t, verified)
}
