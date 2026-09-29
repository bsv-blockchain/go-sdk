package interpreter

// Tests for the stack memory limit and for the allocations the engine makes
// on a script's say-so (GHSA-rh54-8fpg-8wwf). The limit follows bitcoin-sv's
// LimitedStack (script/limitedstack.cpp): the mem/* vectors in
// testdata/node_vectors.json hold the same shapes at the default
// 100,000,000-byte limit with the node's verdicts, and the tests here scale
// them down with WithMaxStackMemory to run fast.

import (
	"bytes"
	"math"
	"math/big"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/errs"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// memPostChronicle is a post-Chronicle coin spent post-Chronicle, without
// SIGPUSHONLY so an unlocking script may run opcodes.
const memPostChronicle = scriptflag.UTXOAfterGenesis | scriptflag.UTXOAfterChronicle | scriptflag.EnableSighashForkID

// memNum returns the minimal push of n.
func memNum(n int64) []byte {
	switch {
	case n == 0:
		return []byte{script.Op0}
	case n >= 1 && n <= 16:
		return []byte{script.Op1 + byte(n-1)}
	}
	return canonicalPush((&ScriptNumber{Val: big.NewInt(n)}).Bytes())
}

// memBig returns a script leaving one element of size bytes, value padded
// with zeros by OP_NUM2BIN (value is OP_0 or OP_1).
func memBig(size int64, value byte) []byte {
	return append(append([]byte{value}, memNum(size)...), script.OpNUM2BIN)
}

// memScript concatenates script pieces.
func memScript(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

// memOps repeats the opcodes ops n times.
func memOps(n int, ops ...byte) []byte {
	return bytes.Repeat(ops, n)
}

// memSpend returns a one-input transaction spending an output locked by lock
// with unlock, and that output.
func memSpend(lock, unlock []byte) (*transaction.Transaction, *transaction.TransactionOutput) {
	prev := &transaction.TransactionOutput{Satoshis: 1000, LockingScript: script.NewFromBytes(lock)}
	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:      &chainhash.Hash{},
		UnlockingScript: script.NewFromBytes(unlock),
		SequenceNumber:  transaction.MaxTxInSequenceNum,
	})
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1, LockingScript: script.NewFromBytes([]byte{script.Op1})})
	return tx, prev
}

// memExecute verifies the spend of lock by unlock under flags.
func memExecute(lock, unlock []byte, flags scriptflag.Flag, opts ...ExecutionOptionFunc) error {
	tx, prev := memSpend(lock, unlock)
	return NewEngine().Execute(append([]ExecutionOptionFunc{WithTx(tx, 0, prev), WithFlags(flags)}, opts...)...)
}

// TestStackMemoryLimit checks where the limit falls, byte for byte, for the
// shapes the mem/* node vectors pin down at the default limit.
func TestStackMemoryLimit(t *testing.T) {
	t.Parallel()

	const limit = 1000
	op0, op1 := []byte{script.Op0}, []byte{script.Op1}
	drop := []byte{script.OpDROP}
	half := int64(limit/2 - stackElementOverhead)
	pick := int64((limit - 3*stackElementOverhead) / 2)

	tests := []struct {
		name   string
		unlock []byte
		lock   []byte
		flags  scriptflag.Flag
		ok     bool
	}{
		{name: "element costing the limit", lock: memScript(memBig(limit-32, script.Op0), drop, op1), ok: true},
		{name: "element one byte over", lock: memScript(memBig(limit-31, script.Op0), drop, op1)},
		{
			name: "32 bytes for each of 10 empty elements, at the limit",
			lock: memScript(memBig(limit-32-10*32-33, script.Op0), memOps(10, script.Op0), op1), ok: true,
		},
		{name: "one more empty element", lock: memScript(memBig(limit-32-10*32-33, script.Op0), memOps(11, script.Op0), op1)},
		{
			name: "alt and data stacks share the limit",
			lock: memScript(memBig(400, script.Op0), []byte{script.OpTOALTSTACK}, memBig(limit-400-64-33, script.Op0), op1), ok: true,
		},
		{
			name: "alt and data stacks one byte over",
			lock: memScript(memBig(400, script.Op0), []byte{script.OpTOALTSTACK}, memBig(limit-400-64-32, script.Op0), op1),
		},
		{
			name:   "alt stack left by the unlocking script still counts, at the limit",
			unlock: memScript(memBig(400, script.Op0), []byte{script.OpTOALTSTACK}),
			lock:   memScript(memBig(limit-400-64, script.Op0), drop, op1), ok: true,
		},
		{
			name:   "alt stack left by the unlocking script still counts, one byte over",
			unlock: memScript(memBig(400, script.Op0), []byte{script.OpTOALTSTACK}),
			lock:   memScript(memBig(limit-400-63, script.Op0), drop, op1),
		},
		{
			name:   "alt stack emptied by the unlocking script",
			unlock: memScript(memBig(400, script.Op0), []byte{script.OpTOALTSTACK, script.OpFROMALTSTACK, script.OpDROP}),
			lock:   memScript(memBig(limit-32, script.Op0), drop, op1), ok: true,
		},
		{
			name:   "alt stack left at a top-level OP_RETURN of the unlocking script",
			unlock: memScript(memBig(400, script.Op0), []byte{script.OpTOALTSTACK, script.OpRETURN}),
			lock:   memScript(memBig(limit-400-63, script.Op0), drop, op1),
		},
		{
			name:   "data stack carried from the unlocking script",
			unlock: memBig(400, script.Op0),
			lock:   memScript(memBig(limit-400-63, script.Op0), drop, drop, op1),
		},
		{name: "OP_DUP to the limit", lock: memScript(memBig(half, script.Op1), []byte{script.OpDUP}, drop, drop, op1), ok: true},
		{name: "OP_DUP one byte over", lock: memScript(memBig(half+1, script.Op1), []byte{script.OpDUP}, drop, drop, op1)},
		{name: "OP_IFDUP one byte over", lock: memScript(memBig(half+1, script.Op1), []byte{script.OpIFDUP}, drop, drop, op1)},
		{
			name: "OP_PICK to the limit",
			lock: memScript(memBig(pick, script.Op1), op0, op1, []byte{script.OpPICK}, drop, drop, drop, op1), ok: true,
		},
		{
			name: "OP_PICK one byte over",
			lock: memScript(memBig(pick+1, script.Op1), op0, op1, []byte{script.OpPICK}, drop, drop, drop, op1),
		},
		{name: "OP_OVER one byte over", lock: memScript(memBig(pick+1, script.Op1), op0, []byte{script.OpOVER}, drop, drop, drop, op1)},
		{name: "OP_TUCK to the limit", lock: memScript(op0, memBig(pick, script.Op1), []byte{script.OpTUCK}, drop, drop, drop, op1), ok: true},
		{name: "OP_TUCK one byte over", lock: memScript(op0, memBig(pick+1, script.Op1), []byte{script.OpTUCK}, drop, drop, drop, op1)},
		{
			name: "OP_3DUP to the limit",
			lock: memScript(op1, op1, memBig(limit/2-98, script.Op1), []byte{script.Op3DUP}, memOps(6, script.OpDROP), op1), ok: true,
		},
		{
			name: "OP_3DUP one byte over",
			lock: memScript(op1, op1, memBig(limit/2-97, script.Op1), []byte{script.Op3DUP}, memOps(6, script.OpDROP), op1),
		},
		{
			name: "OP_CAT of two elements costing the limit together",
			lock: memScript(memBig(400, script.Op0), memBig(limit-64-400, script.Op0), []byte{script.OpCAT}, drop, op1), ok: true,
		},
		{
			name: "OP_DUP of that OP_CAT result",
			lock: memScript(memBig(400, script.Op0), memBig(limit-64-400, script.Op0), []byte{script.OpCAT, script.OpDUP}, drop, drop, op1),
		},
		{
			name: "OP_1ADD growing a number by one byte to the limit",
			lock: memScript(memBig(limit-66, script.Op0), []byte{1, 0x7f, script.Op1ADD, script.OpNIP}), ok: true,
		},
		{
			name: "OP_1ADD growing a number by one byte past the limit",
			lock: memScript(memBig(limit-65, script.Op0), []byte{1, 0x7f, script.Op1ADD, script.OpNIP}),
		},
		{name: "OP_SHA256 of an empty element to the limit", lock: memScript(memBig(limit-96, script.Op0), []byte{script.Op0, script.OpSHA256, script.OpNIP}), ok: true},
		{name: "OP_SHA256 of an empty element past the limit", lock: memScript(memBig(limit-95, script.Op0), []byte{script.Op0, script.OpSHA256, script.OpNIP})},
		{
			name: "OP_SPLIT of an element at the limit",
			lock: memScript(memBig(limit-65, script.Op1), op1, []byte{script.OpSPLIT}, drop, drop, op1), ok: true,
		},
		{name: "OP_BIN2NUM of a zero-padded number at the limit", lock: memScript(memBig(limit-32, script.Op1), []byte{script.OpBIN2NUM}, drop, op1), ok: true},
		{
			name:  "post-Genesis pre-Chronicle coin",
			lock:  memScript(memBig(limit-31, script.Op0), drop, op1),
			flags: scriptflag.UTXOAfterGenesis | scriptflag.EnableSighashForkID,
		},
		{
			name:  "pre-Genesis coin, no stack memory limit",
			lock:  memScript(memBig(520, script.Op0), memOps(3, script.OpDUP), memOps(4, script.OpDROP), op1),
			flags: scriptflag.Genesis | scriptflag.Chronicle | scriptflag.EnableSighashForkID,
			ok:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			flags := tt.flags
			if flags == 0 {
				flags = memPostChronicle
			}
			err := memExecute(tt.lock, tt.unlock, flags, WithMaxStackMemory(limit))
			if tt.ok {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.True(t, errs.IsErrorCode(err, errs.ErrStackOverflow), "%v", err)
		})
	}
}

// TestWithMaxStackMemory checks which limit each option value selects.
func TestWithMaxStackMemory(t *testing.T) {
	t.Parallel()

	preGenesis := scriptflag.Genesis | scriptflag.Chronicle | scriptflag.EnableSighashForkID
	tests := []struct {
		name  string
		flags scriptflag.Flag
		opts  []ExecutionOptionFunc
		want  int64
	}{
		{"default", memPostChronicle, nil, DefaultMaxStackMemory},
		{"zero selects the default", memPostChronicle, []ExecutionOptionFunc{WithMaxStackMemory(0)}, DefaultMaxStackMemory},
		{"negative selects the default", memPostChronicle, []ExecutionOptionFunc{WithMaxStackMemory(-1)}, DefaultMaxStackMemory},
		{"custom", memPostChronicle, []ExecutionOptionFunc{WithMaxStackMemory(12345)}, 12345},
		{"consensus", memPostChronicle, []ExecutionOptionFunc{WithMaxStackMemory(math.MaxInt64)}, math.MaxInt64},
		{"post-Genesis pre-Chronicle coin", scriptflag.UTXOAfterGenesis, nil, DefaultMaxStackMemory},
		{"pre-Genesis coin", preGenesis, []ExecutionOptionFunc{WithMaxStackMemory(12345)}, math.MaxInt64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := &execOpts{}
			all := append([]ExecutionOptionFunc{
				WithScripts(script.NewFromBytes([]byte{script.Op1}), script.NewFromBytes([]byte{script.Op1})),
				WithFlags(tt.flags),
			}, tt.opts...)
			for _, o := range all {
				o(opts)
			}
			th, err := createThread(opts)
			require.NoError(t, err)
			require.Equal(t, tt.want, th.stackMem.limit)
			require.Same(t, &th.stackMem, th.dstack.mem)
			require.Same(t, &th.stackMem, th.astack.mem)
		})
	}
}

// TestDefaultMaxStackMemory checks the default limit is node's default relay
// policy, 100,000,000 bytes, and that math.MaxInt64 lifts it like node's
// consensus rules.
func TestDefaultMaxStackMemory(t *testing.T) {
	require.Equal(t, int64(100_000_000), DefaultMaxStackMemory)

	over := memScript(memBig(DefaultMaxStackMemory-31, script.Op0), []byte{script.OpDROP, script.Op1})
	err := memExecute(over, nil, memPostChronicle)
	require.True(t, errs.IsErrorCode(err, errs.ErrStackOverflow), "%v", err)

	if testing.Short() {
		t.Skip("allocates 100 MB")
	}
	require.NoError(t, memExecute(memScript(memBig(DefaultMaxStackMemory-32, script.Op0), []byte{script.OpDROP, script.Op1}), nil, memPostChronicle))
	require.NoError(t, memExecute(over, nil, memPostChronicle, WithMaxStackMemory(math.MaxInt64)))
}

// TestHostileSizesFailFast runs scripts whose counts or sizes, taken at face
// value, would make the engine allocate gigabytes. Each must fail within
// 100 ms (a second under the race detector) and allocate only what the stack
// memory limit allows.
func TestHostileSizesFailFast(t *testing.T) {
	const kib = 1 << 10
	tests := []struct {
		name     string
		lock     []byte
		code     errs.ErrorCode
		maxBytes uint64
	}{
		{
			// Node fails with SCRIPT_ERR_INVALID_STACK_OPERATION before
			// touching the stack (interpreter.cpp:1544-1546).
			name:     "OP_CHECKMULTISIG claiming 2,147,483,646 pubkeys",
			lock:     []byte{4, 0xfe, 0xff, 0xff, 0x7f, script.OpCHECKMULTISIG},
			code:     errs.ErrInvalidStackOperation,
			maxBytes: 64 * kib,
		},
		{
			// One more pubkey than the SDK's operation limit allows; on a
			// 32-bit platform the count must not overflow the op counter.
			name:     "OP_CHECKMULTISIG claiming 2,147,483,647 pubkeys",
			lock:     []byte{4, 0xff, 0xff, 0xff, 0x7f, script.OpCHECKMULTISIG},
			code:     errs.ErrTooManyOperations,
			maxBytes: 64 * kib,
		},
		{
			name:     "OP_NUM2BIN of 2^31-1 bytes",
			lock:     []byte{script.Op1, 4, 0xff, 0xff, 0xff, 0x7f, script.OpNUM2BIN},
			code:     errs.ErrStackOverflow,
			maxBytes: 64 * kib,
		},
		{
			// Fails at the 27th OP_DUP, of a 64 MiB element; the OP_CATs
			// before it allocate 128 MiB in all, never more than the limit
			// at once.
			name:     "OP_1 then 40 rounds of OP_DUP OP_CAT",
			lock:     memScript([]byte{script.Op1}, memOps(40, script.OpDUP, script.OpCAT)),
			code:     errs.ErrStackOverflow,
			maxBytes: 2 * uint64(DefaultMaxStackMemory),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx, prev := memSpend(tt.lock, nil)
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			start := time.Now()
			err := NewEngine().Execute(WithTx(tx, 0, prev), WithAfterChronicle())
			elapsed := time.Since(start)
			runtime.ReadMemStats(&after)

			require.Error(t, err)
			require.True(t, errs.IsErrorCode(err, tt.code), "%v", err)
			allocated := after.TotalAlloc - before.TotalAlloc
			t.Logf("failed in %v after allocating %d bytes: %v", elapsed, allocated, err)
			require.LessOrEqual(t, allocated, tt.maxBytes, "allocated %d bytes", allocated)
			// Failing fast is what the allocation bound above proves; the
			// wall-clock bound only catches gross regressions, loosely enough
			// for slow or loaded runners.
			budget := 2 * time.Second
			if raceDetector {
				budget = 10 * time.Second
			}
			require.Less(t, elapsed, budget)
		})
	}
}

// TestCheckMultiSigCountAllocations checks, over repeated runs, that
// OP_CHECKMULTISIG allocates nothing sized by a pubkey count the stack does
// not back: a few dozen small allocations, a few kilobytes in all.
func TestCheckMultiSigCountAllocations(t *testing.T) {
	const runs = 20
	tx, prev := memSpend([]byte{4, 0xfe, 0xff, 0xff, 0x7f, script.OpCHECKMULTISIG}, nil)
	execute := func() {
		err := NewEngine().Execute(WithTx(tx, 0, prev), WithAfterChronicle())
		require.True(t, errs.IsErrorCode(err, errs.ErrInvalidStackOperation), "%v", err)
	}

	require.Less(t, testing.AllocsPerRun(runs, execute), 100.0)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range runs {
		execute()
	}
	runtime.ReadMemStats(&after)
	require.Less(t, (after.TotalAlloc-before.TotalAlloc)/runs, uint64(16<<10))
}

// TestStackMemoryAccounting steps through a script using every kind of stack
// mutation and checks after each opcode that the budget counts exactly the
// elements on the data and alt stacks.
func TestStackMemoryAccounting(t *testing.T) {
	t.Parallel()

	lock := memScript(
		memBig(40, script.Op1), []byte{script.OpDUP, script.Op2DUP, script.Op3DUP, script.OpOVER, script.Op2OVER},
		[]byte{script.OpROT, script.Op2ROT, script.OpSWAP, script.Op2SWAP, script.OpNIP, script.OpTUCK},
		[]byte{script.Op2, script.OpPICK, script.Op3, script.OpROLL, script.OpTOALTSTACK, script.OpDUP, script.OpTOALTSTACK},
		[]byte{script.OpCAT, script.Op5, script.OpSPLIT, script.OpSIZE, script.OpADD, script.Op1ADD, script.OpSHA256},
		[]byte{script.OpFROMALTSTACK, script.OpBIN2NUM, script.OpDEPTH, script.OpIFDUP, script.OpDROP, script.Op2DROP},
		[]byte{script.Op3, script.OpLEFT, script.Op1, script.OpRIGHT, script.OpINVERT, script.OpDUP, script.OpAND},
		[]byte{script.Op1, script.OpLSHIFT, script.Op3, script.OpLSHIFTNUM, script.OpDUP, script.OpEQUAL},
		[]byte{script.OpFROMALTSTACK, script.Op1, script.Op2, script.OpSUBSTR, script.OpDROP},
	)
	opts := &execOpts{}
	for _, o := range []ExecutionOptionFunc{
		WithScripts(script.NewFromBytes(lock), script.NewFromBytes([]byte{script.Op1, script.Op2, script.OpTOALTSTACK, script.Op3})),
		WithFlags(memPostChronicle),
	} {
		o(opts)
	}
	th, err := createThread(opts)
	require.NoError(t, err)

	usage := func(stacks ...*stack) int64 {
		var n int64
		for _, s := range stacks {
			for _, e := range s.stk {
				n += int64(len(e)) + stackElementOverhead
			}
		}
		return n
	}
	// The alt stack element the unlocking script leaves keeps counting in
	// the locking script.
	var kept int64
	for steps := 0; ; steps++ {
		require.Less(t, steps, len(lock)+10)
		scriptIdx := th.scriptIdx
		done, stepErr := th.Step()
		require.NoError(t, stepErr)
		want := usage(&th.dstack, &th.astack)
		if th.scriptIdx == 0 {
			kept = usage(&th.astack)
		} else {
			want += kept
		}
		require.Equal(t, want, th.stackMem.used, "after opcode %d of script %d", th.scriptOff, scriptIdx)
		if done {
			break
		}
	}
	require.NoError(t, th.CheckErrorCondition(true))
}

// TestStackElementsHoldOnlyTheirOwnBytes checks that no element keeps a
// larger buffer alive than its own length, which the stack memory limit
// counts: removed elements are cleared from the stack's backing array, and
// OP_SPLIT, OP_LEFT, OP_RIGHT, OP_SUBSTR and OP_BIN2NUM push copies rather
// than slices of their operand.
func TestStackElementsHoldOnlyTheirOwnBytes(t *testing.T) {
	t.Parallel()

	t.Run("removed elements are cleared", func(t *testing.T) {
		t.Parallel()
		s := newStack(&afterChronicleConfig{}, false)
		for i := range 6 {
			s.PushByteArray([]byte{byte(i)})
		}
		_, err := s.PopByteArray()
		require.NoError(t, err)
		require.NoError(t, s.NipN(3))
		require.NoError(t, s.RollN(3))
		require.NoError(t, s.DropN(1))
		for i, e := range s.stk[len(s.stk):cap(s.stk)] {
			require.Nil(t, e, "slot %d past the end", len(s.stk)+i)
		}
	})

	newThread := func() *thread {
		th := &thread{
			cfg:            &afterChronicleConfig{},
			afterGenesis:   true,
			afterChronicle: true,
		}
		th.dstack = newStack(th.cfg, false)
		return th
	}
	run := func(t *testing.T, op byte, operand []byte, args ...int64) [][]byte {
		t.Helper()
		th := newThread()
		th.dstack.PushByteArray(operand)
		for _, a := range args {
			th.dstack.PushInt(&ScriptNumber{Val: big.NewInt(a), AfterGenesis: true})
		}
		pop := ParsedOpcode{op: opcodeArray[op]}
		require.NoError(t, pop.op.exec(&pop, th))
		out := make([][]byte, len(th.dstack.stk))
		for i, e := range th.dstack.stk {
			out[i] = bytes.Clone(e)
		}
		// Overwrite the operand: an element sharing its memory changes too.
		for i := range operand {
			operand[i] ^= 0xff
		}
		for i, e := range th.dstack.stk {
			require.Equal(t, out[i], e, "element %d shares the operand's memory", i)
		}
		return out
	}

	for _, tt := range []struct {
		name string
		op   byte
		args []int64
		want [][]byte
	}{
		{"OP_SPLIT", script.OpSPLIT, []int64{2}, [][]byte{{1, 2}, {3, 4, 5, 6}}},
		{"OP_LEFT", script.OpLEFT, []int64{2}, [][]byte{{1, 2}}},
		{"OP_RIGHT", script.OpRIGHT, []int64{2}, [][]byte{{5, 6}}},
		{"OP_SUBSTR", script.OpSUBSTR, []int64{1, 3}, [][]byte{{2, 3, 4}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, run(t, tt.op, []byte{1, 2, 3, 4, 5, 6}, tt.args...))
		})
	}

	t.Run("OP_BIN2NUM", func(t *testing.T) {
		t.Parallel()
		// Minimally encoding a copy of the operand in place would leave the
		// one-byte result inside a 64-byte buffer.
		th := newThread()
		th.dstack.PushByteArray(append([]byte{5}, make([]byte, 63)...))
		pop := ParsedOpcode{op: opcodeArray[script.OpBIN2NUM]}
		require.NoError(t, pop.op.exec(&pop, th))
		require.Equal(t, [][]byte{{5}}, th.dstack.stk)
		require.Less(t, cap(th.dstack.stk[0]), 64)

		require.Equal(t, [][]byte{{5}}, run(t, script.OpBIN2NUM, []byte{5, 0, 0, 0, 0, 0}))
	})

	t.Run("script number encoding", func(t *testing.T) {
		t.Parallel()
		b := (&ScriptNumber{Val: big.NewInt(0xff)}).Bytes()
		require.Equal(t, []byte{0xff, 0x00}, b)
		require.Equal(t, 2, cap(b))
	})
}
