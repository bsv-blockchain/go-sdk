package spv

// Tests that Verify's ctx bounds the scripts it runs: a spend of an output
// whose locking script inverts a 99 MB element thousands of times stops at
// the deadline (script/interpreter's TestWithContextDeadlineStopsLongRun
// runs the same shape through the engine alone).

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// dosLockingScript returns a costly locking script: OP_0 <99000000>
// OP_NUM2BIN builds one ~99,000,000-byte element -- just under the default
// 100,000,000-byte stack memory limit -- then n passes of OP_INVERT walk
// over every byte of it (about 30 ms per pass), before
// OP_DROP OP_1 leaves a truthy result. Run to completion this keeps a
// single script execution busy for seconds to hours depending on n; a
// context deadline must stop it long before that.
func dosLockingScript(t *testing.T, n int) *script.Script {
	t.Helper()
	s := &script.Script{}
	require.NoError(t, s.AppendOpcodes(script.Op0))
	require.NoError(t, s.AppendBigInt(*big.NewInt(99_000_000)))
	require.NoError(t, s.AppendOpcodes(script.OpNUM2BIN))
	for range n {
		require.NoError(t, s.AppendOpcodes(script.OpINVERT))
	}
	require.NoError(t, s.AppendOpcodes(script.OpDROP, script.Op1))
	return s
}

// TestSPVVerifyContextDeadlineStopsScriptExecution checks that ctx bounds
// Verify end to end: a parent output whose locking script is
// dosLockingScript, proven mined post-Chronicle against a gullible tracker
// (GullibleHeadersClient confirms any root at any height, so this needs no
// real chain), spent by an unmined child with an empty unlocking script.
// Without WithContext threaded into the script execution inside verifyTx,
// this would keep Verify busy for a very long time on this one input; with
// it, Verify must return close to the deadline, and ctx's own error must
// still be visible through errors.Is alongside ErrScriptVerificationFailed
// (fmt.Errorf's two %w verbs keep both wrapped, see verifyTx).
func TestSPVVerifyContextDeadlineStopsScriptExecution(t *testing.T) {
	lock := dosLockingScript(t, 3000)
	src := minedSource(t, lock, mainnetChronicleHeight+1)

	child := transaction.NewTransaction()
	child.AddInputFromTx(src, 0, nil)
	child.Inputs[0].UnlockingScript = &script.Script{}
	child.AddOutput(&transaction.TransactionOutput{Satoshis: 40_000, LockingScript: opTrue})

	const deadline = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	start := time.Now()
	verified, err := Verify(ctx, child, &GullibleHeadersClient{}, nil)
	elapsed := time.Since(start)

	require.Error(t, err)
	require.False(t, verified)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorIs(t, err, ErrScriptVerificationFailed)
	require.Less(t, elapsed, deadline+2*time.Second,
		"Verify should stop near the deadline, not run all OP_INVERT passes to completion")
}

// TestSPVVerifyNoDeadlineUnaffected checks that a small version of the same
// script (few enough OP_INVERT passes to run quickly either way) still
// verifies normally with a context.Context carrying no deadline, so
// threading g.ctx into the interpreter does not change an ordinary Verify
// call's outcome.
func TestSPVVerifyNoDeadlineUnaffected(t *testing.T) {
	lock := dosLockingScript(t, 1)
	src := minedSource(t, lock, mainnetChronicleHeight+1)

	child := transaction.NewTransaction()
	child.AddInputFromTx(src, 0, nil)
	child.Inputs[0].UnlockingScript = &script.Script{}
	child.AddOutput(&transaction.TransactionOutput{Satoshis: 40_000, LockingScript: opTrue})

	verified, err := Verify(t.Context(), child, &GullibleHeadersClient{}, nil)
	require.NoError(t, err)
	require.True(t, verified)
}
