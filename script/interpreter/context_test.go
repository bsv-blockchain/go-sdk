// Copyright (c) 2025 The bsv-blockchain/go-sdk developers
// Use of this source code is governed by an ISC license that can be found in the LICENSE file.

// Tests for WithContext: a pre-cancelled context fails before any opcode
// runs, a huge element inverted over and over stops close to the deadline,
// the loops inside OP_CHECKMULTISIG, OP_LSHIFT and OP_RSHIFT notice
// cancellation mid-opcode, and execution without WithContext is unchanged.
package interpreter

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/errs"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// opcodeCounter is a Debugger that counts how many opcodes actually started
// executing, so a test can prove execution stopped before any of them ran.
type opcodeCounter struct {
	nopDebugger

	n int
}

func (d *opcodeCounter) BeforeExecuteOpcode(*State) {
	d.n++
}

// cancelBeforeOpcode cancels ctx the instant the named opcode is about to
// execute: after Step's own per-opcode context check has already passed for
// it (BeforeExecuteOpcode fires only once Step has decided to run the
// opcode), and before the opcode itself does any work. This isolates an
// in-loop check inside that opcode from the per-opcode check in Step, which
// would otherwise also explain a cancellation error.
type cancelBeforeOpcode struct {
	nopDebugger

	op     byte
	cancel context.CancelFunc
	fired  bool
}

func (d *cancelBeforeOpcode) BeforeExecuteOpcode(s *State) {
	if !d.fired && s.Opcode().Value() == d.op {
		d.fired = true
		d.cancel()
	}
}

// TestWithContextPreCancelledFailsBeforeRunning checks that a context.Context
// that is already done when Execute is called is rejected before any opcode
// runs, not merely before the script finishes.
func TestWithContextPreCancelledFailsBeforeRunning(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	counter := &opcodeCounter{}
	err := memExecute([]byte{script.Op1}, nil, memPostChronicle, WithContext(ctx), WithDebugger(counter))

	require.Error(t, err)
	require.True(t, errs.IsErrorCode(err, errs.ErrExecutionCancelled), "got %v", err)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 0, counter.n, "no opcode should have started executing")
}

// TestWithContextDeadlineStopsLongRun runs a costly script: a single
// ~99,000,000-byte element built with OP_NUM2BIN, then many OP_INVERT passes
// over it. Each pass costs about 30 ms; without a budget, thousands of them
// would keep Execute busy for minutes. With a
// short deadline, Execute must return close to the deadline plus at most one
// more opcode's worth of work, not after every pass has run.
func TestWithContextDeadlineStopsLongRun(t *testing.T) {
	t.Parallel()

	passes := func(n int) []byte {
		return memScript(memBig(99_000_000, script.Op0), memOps(n, script.OpINVERT), []byte{script.Op1})
	}

	// Scale the bound to this machine: under -race on a loaded CI runner a
	// single pass over 99MB can take seconds, and the context is only
	// checked between opcodes. Running all 3000 passes would take about
	// 3000 of these; stopping near the deadline takes a handful.
	start := time.Now()
	require.NoError(t, memExecute(passes(1), nil, memPostChronicle))
	onePass := time.Since(start)

	const deadline = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	start = time.Now()
	err := memExecute(passes(3000), nil, memPostChronicle, WithContext(ctx))
	elapsed := time.Since(start)

	require.Error(t, err)
	require.True(t, errs.IsErrorCode(err, errs.ErrExecutionCancelled), "got %v", err)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, elapsed, deadline+max(2*time.Second, 100*onePass),
		"execution should stop near the deadline, not after all 3000 OP_INVERT passes (one pass: %v)", onePass)
}

// multiSigLoopScript returns a locking script that runs OP_CHECKMULTISIG
// with n pubkeys and n signatures: n copies of one syntactically valid but
// never-matching (signature, pubkey) pair, so every one of the n loop
// iterations does real work -- a pubkey-format check and a real EC point
// decompression attempt in ec.ParsePubKey -- without ever succeeding early
// (which would shrink the loop below n iterations).
func multiSigLoopScript(n int) []byte {
	// Minimal DER signature (R=S=1, 0x30 0x06 0x02 0x01 0x01 0x02 0x01
	// 0x01), plus a hash type with FORKID set (required since Execute with
	// no flag option enables SIGHASH_FORKID, which forces STRICTENC).
	// checkSignatureEncoding only checks DER shape and low-S; it never
	// verifies the signature cryptographically, so this parses and passes
	// encoding checks without ever being a real signature over anything.
	sig := append([]byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, byte(sighash.AllForkID))
	// A correctly shaped (33-byte, 0x02-prefixed) but off-curve pubkey:
	// passes checkPubKeyEncoding's format-only check, forcing
	// ec.ParsePubKey to attempt a real point decompression every iteration.
	pubKey := append([]byte{0x02}, bytes.Repeat([]byte{0x11}, 32)...)

	s := canonicalPush(nil) // the multisig dummy argument
	for range n {
		s = append(s, canonicalPush(sig)...)
	}
	s = append(s, memNum(int64(n))...)
	for range n {
		s = append(s, canonicalPush(pubKey)...)
	}
	s = append(s, memNum(int64(n))...)
	return append(s, script.OpCHECKMULTISIG)
}

// TestWithContextCheckMultiSigCancelledInsideLoop checks that
// OP_CHECKMULTISIG's signature loop notices a context.Context that becomes
// done while the opcode itself is running, rather than only on the next
// opcode boundary (which, since OP_CHECKMULTISIG is this script's last
// opcode, would otherwise mean the script's own ErrEvalFalse verdict).
func TestWithContextCheckMultiSigCancelledInsideLoop(t *testing.T) {
	t.Parallel()

	const n = 500
	lock := multiSigLoopScript(n)

	// Sanity: without cancellation the script is well formed and reaches a
	// normal verdict -- every signature is fabricated, so CHECKMULTISIG
	// fails cleanly, not some unrelated setup error.
	baseErr := memExecute(lock, nil, memPostChronicle)
	require.True(t, errs.IsErrorCode(baseErr, errs.ErrEvalFalse), "got %v", baseErr)

	ctx, cancel := context.WithCancel(context.Background())
	dbg := &cancelBeforeOpcode{op: script.OpCHECKMULTISIG, cancel: cancel}

	err := memExecute(lock, nil, memPostChronicle, WithContext(ctx), WithDebugger(dbg))

	require.Error(t, err)
	require.True(t, errs.IsErrorCode(err, errs.ErrExecutionCancelled), "got %v", err)
	require.ErrorIs(t, err, context.Canceled)
	require.True(t, dbg.fired, "the debugger never saw OP_CHECKMULTISIG start")
}

// shiftLoopScript returns a locking script that builds a size-byte element
// (the number 1, via OP_NUM2BIN) and shifts it by one bit with op (OP_LSHIFT
// or OP_RSHIFT). The shift is the last opcode, so no later Step checks the
// context: only the check inside the shift's own loop can stop it.
func shiftLoopScript(size int64, op byte) []byte {
	return memScript(memBig(size, script.Op1), memNum(1), []byte{op})
}

// TestWithContextShiftCancelledInsideLoop checks that OP_LSHIFT's and
// OP_RSHIFT's loops notice a context.Context that becomes done while the
// opcode itself is running (node checks inside them, interpreter.cpp:1144,
// 1178). The shift is the script's last opcode, so without the in-loop check
// the script would end with its own verdict. The element is three times
// checkContextEvery so the loop crosses more than one check point.
func TestWithContextShiftCancelledInsideLoop(t *testing.T) {
	t.Parallel()

	const size = 3 * checkContextEvery

	for _, op := range []byte{script.OpLSHIFT, script.OpRSHIFT} {
		lock := shiftLoopScript(size, op)

		// Sanity: without cancellation the script is well formed and
		// reaches a normal verdict.
		require.NoError(t, memExecute(lock, nil, memPostChronicle), "op %#x", op)

		ctx, cancel := context.WithCancel(context.Background())
		dbg := &cancelBeforeOpcode{op: op, cancel: cancel}

		err := memExecute(lock, nil, memPostChronicle, WithContext(ctx), WithDebugger(dbg))

		require.Error(t, err, "op %#x", op)
		require.True(t, errs.IsErrorCode(err, errs.ErrExecutionCancelled), "op %#x: got %v", op, err)
		require.ErrorIs(t, err, context.Canceled, "op %#x", op)
		require.True(t, dbg.fired, "op %#x: the debugger never saw the shift opcode start", op)
	}
}

// TestWithContextUnsetOrBackgroundUnchanged checks that omitting WithContext,
// passing a nil context.Context, and passing context.Background() (whose
// Done() channel is also nil) all behave exactly as before this option
// existed: no cancellation check ever fires.
func TestWithContextUnsetOrBackgroundUnchanged(t *testing.T) {
	t.Parallel()

	lock := []byte{script.Op1}

	require.NoError(t, memExecute(lock, nil, memPostChronicle))
	require.NoError(t, memExecute(lock, nil, memPostChronicle, WithContext(nil))) //nolint:staticcheck // SA1012 -- documenting that a nil ctx is accepted and disables the check
	require.NoError(t, memExecute(lock, nil, memPostChronicle, WithContext(context.Background())))
}
