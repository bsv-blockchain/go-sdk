// Copyright (c) 2025 The bsv-blockchain/go-sdk developers
// Use of this source code is governed by an ISC license that can be found in the LICENSE file.

// Regression tests for the numeric-opcode area of GHSA-rh54-8fpg-8wwf
// (script/interpreter/number.go, config.go, stack.go, and the
// arithmetic/splice/bitwise opcodes in operations.go). Every table-driven
// case below embeds a tx/lock pair that was differentially checked against
// the real bitcoin-sv node (via gobdk) during the fix's development; the
// expected verdict recorded here is the node's verdict, which the SDK must
// now match. Helper names are prefixed with "num" to avoid clashing with
// the signature/checksig area's own test file.
package interpreter

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// numExecHex decodes a full spending tx and a single previous-output locking
// script (both hex, as in the cases verified against bitcoin-sv (GoBDK)) and
// executes input 0 against the given options.
func numExecHex(t *testing.T, txHex, lockHex string, sats uint64, opts ...ExecutionOptionFunc) error {
	t.Helper()

	tx, err := transaction.NewTransactionFromHex(txHex)
	require.NoError(t, err)

	lockBytes, err := hex.DecodeString(lockHex)
	require.NoError(t, err)

	prevOut := &transaction.TransactionOutput{
		LockingScript: script.NewFromBytes(lockBytes),
		Satoshis:      sats,
	}
	tx.Inputs[0].SetSourceTxOutput(prevOut)

	allOpts := append([]ExecutionOptionFunc{WithTx(tx, 0, prevOut)}, opts...)
	return NewEngine().Execute(allOpts...)
}

// The node flag-word "eras" exercised by GHSA-rh54-8fpg-8wwf's numeric test
// cases, expressed as the equivalent SDK ExecutionOptionFuncs rather than as
// a raw node bitmask.
//
//   - numOptsConsensusPostChronicle:  node word 0x3d462f -- post-Chronicle
//     coin and spend, consensus (block-validation) checks only.
//   - numOptsPolicyPostChronicle:     node word 0x3d47ff -- same era, but
//     with the policy-only bits (NULLDUMMY/MINIMALDATA/DISCOURAGE/
//     CLEANSTACK) also set, as a relay/mempool node would check.
//   - numOptsConsensusPostGenesisPreChronicleCoin: node word 0x1d462f --
//     coin created after Genesis but before Chronicle, spent in a
//     post-Chronicle block (so the SPEND is validated under Chronicle's
//     non-malleability rules, but the COIN's own era caps
//     MaxScriptNumberLength() at 750,000 instead of 32,000,000).
func numOptsConsensusPostChronicle() []ExecutionOptionFunc {
	return []ExecutionOptionFunc{
		WithAfterChronicle(),
		WithChronicle(),
		WithForkID(),
		WithFlags(scriptflag.Bip16 | scriptflag.VerifyStrictEncoding | scriptflag.VerifyDERSignatures |
			scriptflag.VerifyLowS | scriptflag.VerifySigPushOnly | scriptflag.VerifyCheckLockTimeVerify |
			scriptflag.VerifyCheckSequenceVerify | scriptflag.VerifyNullFail),
	}
}

func numOptsPolicyPostChronicle() []ExecutionOptionFunc {
	return append(numOptsConsensusPostChronicle(),
		WithFlags(scriptflag.StrictMultiSig|scriptflag.VerifyMinimalData|
			scriptflag.DiscourageUpgradableNops|scriptflag.VerifyCleanStack))
}

func numOptsConsensusPostGenesisPreChronicleCoin() []ExecutionOptionFunc {
	return []ExecutionOptionFunc{
		WithAfterGenesis(),
		WithChronicle(),
		WithForkID(),
		WithFlags(scriptflag.Bip16 | scriptflag.VerifyStrictEncoding | scriptflag.VerifyDERSignatures |
			scriptflag.VerifyLowS | scriptflag.VerifySigPushOnly | scriptflag.VerifyCheckLockTimeVerify |
			scriptflag.VerifyCheckSequenceVerify | scriptflag.VerifyNullFail),
	}
}

// TestGHSANumOracleCases embeds the GHSA-rh54-8fpg-8wwf numeric-opcode
// reproducers (OP_NUM2BIN size limits, shift count range and rounding,
// OP_SUBSTR/OP_SPLIT operand decode, OP_MUL result size and huge shift and
// pick counts, plus the advisory's own class 4/5/6/7 and DoS reproducers) so
// they run without GoBDK. Each expected verdict is the real bitcoin-sv node's
// verdict for that exact tx/lock/era combination.
func TestGHSANumOracleCases(t *testing.T) {
	const baseTx = "02000000010282f68044beaa91d8f3424e5499046c9a2fc62222344f786bdf10882a0dcb050000000000ffffffff010100000000000000015100000000"
	const shiftTx = "0200000001829896aed1733429283adb214280217591f00929568490f2c8530c8a9f7260310000000000ffffffff010100000000000000015100000000"
	const rshiftNegTx = "0200000001cdb466d496ab751215f206525043397d479d1546571478bdc06ec72c9434ce450000000000ffffffff010100000000000000015100000000"
	const substrTx = "0200000001bd713e289714213b3d76b5168a550fe3bc8bee30363eb9a72795e051c88686500000000000ffffffff010100000000000000015100000000"

	tests := []struct {
		name      string
		rule      string
		tx        string
		lock      string
		opts      []ExecutionOptionFunc
		wantValid bool
		heavy     bool // multi-MB / slow (>2s); skipped under -short
	}{
		{
			name:      "num2bin N=32,000,000 exact node limit",
			rule:      "OP_NUM2BIN size limit",
			tx:        baseTx,
			lock:      "51040048e801808b7551",
			opts:      numOptsConsensusPostChronicle(),
			wantValid: true,
		},
		{
			name:      "num2bin N=32,000,001 (>node limit)",
			rule:      "OP_NUM2BIN size limit",
			tx:        baseTx,
			lock:      "51040148e801808b7551",
			opts:      numOptsConsensusPostChronicle(),
			wantValid: false,
		},
		{
			name:      "num2bin N=33,554,432 (old, wrong SDK limit)",
			rule:      "OP_NUM2BIN size limit",
			tx:        baseTx,
			lock:      "510400000002808b7551",
			opts:      numOptsConsensusPostChronicle(),
			wantValid: false,
		},
		{
			name:      "num2bin N=33,554,433 (over both limits)",
			rule:      "OP_NUM2BIN size limit",
			tx:        baseTx,
			lock:      "510401000002808b7551",
			opts:      numOptsConsensusPostChronicle(),
			wantValid: false,
		},
		{
			name:      "num2bin N=750,000 Genesis-era exact limit",
			rule:      "OP_NUM2BIN size limit",
			tx:        baseTx,
			lock:      "5103b0710b808b7551",
			opts:      numOptsConsensusPostGenesisPreChronicleCoin(),
			wantValid: true,
		},
		{
			name:      "RSHIFTNUM count=INT_MAX+1 (consensus)",
			rule:      "shift count above INT_MAX",
			tx:        shiftTx,
			lock:      "51050000008000b77551",
			opts:      numOptsConsensusPostChronicle(),
			wantValid: false,
		},
		{
			name:      "RSHIFTNUM count=INT_MAX+1 (policy)",
			rule:      "shift count above INT_MAX",
			tx:        shiftTx,
			lock:      "51050000008000b77551",
			opts:      numOptsPolicyPostChronicle(),
			wantValid: false,
		},
		{
			name:      "-3 RSHIFTNUM 3 == 0, round toward zero (consensus)",
			rule:      "RSHIFTNUM rounds toward zero",
			tx:        rshiftNegTx,
			lock:      "018353b70087",
			opts:      numOptsConsensusPostChronicle(),
			wantValid: true,
		},
		{
			name:      "-3 RSHIFTNUM 3 == 0, round toward zero (policy)",
			rule:      "RSHIFTNUM rounds toward zero",
			tx:        rshiftNegTx,
			lock:      "018353b70087",
			opts:      numOptsPolicyPostChronicle(),
			wantValid: true,
		},
		{
			name:      "OP_SUBSTR 9-byte BEGIN operand decodes to +4",
			rule:      "OP_SUBSTR legacy operand decode",
			tx:        substrTx,
			lock:      "10000102030405060708090a0b0c0d0e0f0904000000000000008054b3040405060787",
			opts:      numOptsConsensusPostChronicle(),
			wantValid: true,
		},
		{
			name:      "OP_SUBSTR 9-byte LEN operand decodes to +4",
			rule:      "OP_SUBSTR legacy operand decode",
			tx:        baseTx,
			lock:      "1400000000000000000000000000000000000000000009040000000000000080b37551",
			opts:      numOptsConsensusPostChronicle(),
			wantValid: true,
		},
		{
			name:      "OP_SUBSTR 8-byte control (non-divergent boundary)",
			rule:      "OP_SUBSTR legacy operand decode",
			tx:        baseTx,
			lock:      "14000000000000000000000000000000000000000000080100000000000000b37551",
			opts:      numOptsConsensusPostChronicle(),
			wantValid: true,
		},
		{
			name:      "OP_SPLIT 9-byte operand (must NOT use the legacy decode)",
			rule:      "OP_SUBSTR legacy operand decode",
			tx:        baseTx,
			lock:      "0401020304090400000000000000807f",
			opts:      numOptsConsensusPostChronicle(),
			wantValid: false,
		},
		{
			name:      "LSHIFTNUM count=INT_MAX must fail fast, not hang",
			rule:      "LSHIFTNUM pre-shift width check",
			tx:        baseTx,
			lock:      "5104ffffff7fb67551",
			opts:      numOptsConsensusPostChronicle(),
			wantValid: false,
		},
		{
			name:      "OP_MUL chain exceeding the 750,000-byte pre-Chronicle limit",
			rule:      "OP_MUL result size limit",
			tx:        baseTx,
			lock:      "04ffffff7f769576957695769576957695769576957695769576957695769576957695769576957695",
			opts:      numOptsConsensusPostGenesisPreChronicleCoin(),
			wantValid: false,
		},
		{
			name:      "OP_MUL chain control, stays under the 750,000-byte limit",
			rule:      "OP_MUL result size limit",
			tx:        baseTx,
			lock:      "04ffffff7f7695769576957695769576957695769576957695769576957695",
			opts:      numOptsConsensusPostGenesisPreChronicleCoin(),
			wantValid: true,
		},
		{
			name:      "OP_MUL chain exceeding the 32,000,000-byte post-Chronicle limit",
			rule:      "OP_MUL result size limit",
			tx:        baseTx,
			lock:      "04ffffff7f76957695769576957695769576957695769576957695769576957695769576957695769576957695769576957695",
			opts:      numOptsConsensusPostChronicle(),
			wantValid: false,
			heavy:     true,
		},
		{
			name:      "OP_LSHIFT with shift count = 2^64",
			rule:      "huge shift and pick counts",
			tx:        baseTx,
			lock:      "01ff0900000000000000000198010087",
			opts:      numOptsConsensusPostGenesisPreChronicleCoin(),
			wantValid: true,
		},
		{
			name:      "OP_RSHIFT with shift count = 2^64+3",
			rule:      "huge shift and pick counts",
			tx:        baseTx,
			lock:      "01ff0903000000000000000199010087",
			opts:      numOptsConsensusPostGenesisPreChronicleCoin(),
			wantValid: true,
		},
		{
			name:      "OP_LSHIFT with shift count = 2^33 (control)",
			rule:      "huge shift and pick counts",
			tx:        baseTx,
			lock:      "01ff05000000000298010087",
			opts:      numOptsConsensusPostGenesisPreChronicleCoin(),
			wantValid: true,
		},
		{
			name:      "OP_PICK with count = 2^64 on a 3-item stack",
			rule:      "huge shift and pick counts",
			tx:        baseTx,
			lock:      "0101010201030900000000000000000179",
			opts:      numOptsConsensusPostGenesisPreChronicleCoin(),
			wantValid: false,
		},
		{
			// Advisory reproducer "4 gen-00009": the same lock as the
			// N=32,000,001 case above, under the advisory's own original word.
			name:      "advisory-4 gen-00009 NUM LEN 32MB",
			rule:      "OP_NUM2BIN size limit",
			tx:        baseTx,
			lock:      "51040148e801808b7551",
			opts:      numOptsConsensusPostChronicle(),
			wantValid: false,
		},
		{
			// Advisory reproducer "DoS gen-00813": must reject in
			// milliseconds, not hang -- see TestGHSANumLSHIFTNUMDoSIsFast
			// below for the explicit timing assertion.
			name:      "advisory-DoS gen-00813 LSHIFTNUM count=INT_MAX",
			rule:      "LSHIFTNUM pre-shift width check",
			tx:        shiftTx,
			lock:      "5104ffffff7fb67551",
			opts:      numOptsConsensusPostChronicle(),
			wantValid: false,
		},
		{
			name:      "advisory-DoS gen-00815 LSHIFTNUM count=INT_MAX+1",
			rule:      "shift count above INT_MAX",
			tx:        shiftTx,
			lock:      "51050000008000b67551",
			opts:      numOptsConsensusPostChronicle(),
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.heavy {
				if testing.Short() {
					t.Skip("heavy multi-MB OP_MUL case; skipped under -short")
				}
			} else {
				t.Parallel()
			}

			err := numExecHex(t, tt.tx, tt.lock, 1000, tt.opts...)
			if tt.wantValid {
				require.NoError(t, err, "rule %s: expected script to validate", tt.rule)
			} else {
				require.Error(t, err, "rule %s: expected script to be rejected", tt.rule)
			}
		})
	}
}

// TestGHSANumLSHIFTNUMDoSIsFast is the DoS half of the LSHIFTNUM
// count=INT_MAX and INT_MAX+1 cases above: before the fix, a tiny
// OP_LSHIFTNUM script with a huge shift count would hang the SDK for
// minutes to hours (O(n^2) Bytes() plus no pre-shift width check). It must
// now reject in well under a second.
func TestGHSANumLSHIFTNUMDoSIsFast(t *testing.T) {
	const tx = "0200000001829896aed1733429283adb214280217591f00929568490f2c8530c8a9f7260310000000000ffffffff010100000000000000015100000000"

	cases := []struct {
		name string
		lock string
	}{
		{"gen-00813 count=INT_MAX", "5104ffffff7fb67551"},
		{"gen-00815 count=INT_MAX+1", "51050000008000b67551"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			// Build the tx/script on this goroutine (require is fine here);
			// only the actual Execute() call -- the one that might hang --
			// runs on the background goroutine below, since testify's
			// require must never be called off the test's own goroutine.
			txn, err := transaction.NewTransactionFromHex(tx)
			require.NoError(t, err)
			lockBytes, err := hex.DecodeString(c.lock)
			require.NoError(t, err)
			prevOut := &transaction.TransactionOutput{LockingScript: script.NewFromBytes(lockBytes), Satoshis: 1000}
			txn.Inputs[0].SetSourceTxOutput(prevOut)
			opts := append([]ExecutionOptionFunc{WithTx(txn, 0, prevOut)}, numOptsConsensusPostChronicle()...)

			done := make(chan error, 1)
			go func() {
				done <- NewEngine().Execute(opts...)
			}()

			select {
			case execErr := <-done:
				require.Error(t, execErr)
			case <-time.After(2 * time.Second):
				t.Fatal("OP_LSHIFTNUM with a huge shift count did not reject within 2s")
			}
		})
	}
}

// --- Focused unit tests for the new helpers -------------------------------

func TestGHSANumLegacyDeserializeInt64(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want int64
	}{
		{"empty is zero", nil, 0},
		{"1 byte positive", hexToBytes("04"), 4},
		{"1 byte negative", hexToBytes("84"), -4},
		{"8 byte max positive (sign-magnitude, well-defined)", hexToBytes("ffffffffffffff7f"), math.MaxInt64},
		{"8 byte, mirrors general decode", hexToBytes("ffffffffffffffff"), -9223372036854775807},
		{
			// The advisory's own 9-byte reproducer: node decodes this to
			// +4 by reinterpreting bytes[0:8] as a raw little-endian
			// int64 and discarding byte 8 (0x80) entirely, NOT by
			// sign-magnitude decoding all 9 bytes (which would give -4,
			// the general MakeScriptNumber path's answer).
			name: "9 byte: raw reinterpretation of bytes[0:8], byte 8 discarded",
			in:   hexToBytes("0400000000000000" + "80"),
			want: 4,
		},
		{
			name: "9 byte all-0xff: low 8 bytes as raw two's complement",
			in:   hexToBytes("ffffffffffffffff" + "01"),
			want: -1,
		},
		{
			// Byte 8 is ORed into byte slot 0 (the compiled node's shift
			// count wraps mod 64); only the last byte is discarded. The
			// real node decodes this to 132 (GHSA-rh54-8fpg-8wwf).
			name: "10 byte: byte 8 folds into slot 0, last byte discarded",
			in:   hexToBytes("0400000000000000" + "8000"),
			want: 0x84,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := legacyDeserializeInt64(tt.in)
			require.Equal(t, tt.want, got)
		})
	}
}

// numNewStack builds a bare, post-Genesis *stack for unit-testing stack
// methods directly, wiring up the no-op debug/state-handler hooks the zero
// value is missing (mirroring how thread.go constructs a standalone stack,
// e.g. its else stack: &stack{debug: &nopDebugger{}, sh: &nopStateHandler{}}).
func numNewStack(maxLen int, verifyMinimal bool) *stack {
	return &stack{
		maxNumLength:      maxLen,
		afterGenesis:      true,
		verifyMinimalData: verifyMinimal,
		debug:             &nopDebugger{},
		sh:                &nopStateHandler{},
	}
}

func TestGHSANumPopLegacyInt(t *testing.T) {
	t.Run("applies the length cap before decoding", func(t *testing.T) {
		s := numNewStack(4, false)
		s.PushByteArray(make([]byte, 5))
		_, err := s.PopLegacyInt()
		require.Error(t, err)
	})

	t.Run("applies minimal-encoding before decoding", func(t *testing.T) {
		s := numNewStack(100, true)
		s.PushByteArray(hexToBytes("0100")) // non-minimal encoding of 1
		_, err := s.PopLegacyInt()
		require.Error(t, err)
	})

	t.Run("9-byte operand uses the legacy decode, not sign-magnitude", func(t *testing.T) {
		s := numNewStack(100, false)
		s.PushByteArray(hexToBytes("0400000000000000" + "80"))
		v, err := s.PopLegacyInt()
		require.NoError(t, err)
		require.Equal(t, int32(4), v)
	})
}

func TestGHSANumHexPreview(t *testing.T) {
	require.Empty(t, hexPreview(nil))
	require.Equal(t, "0102", hexPreview([]byte{0x01, 0x02}))

	big := make([]byte, hexPreviewLen+100)
	got := hexPreview(big)
	require.Contains(t, got, "...")
	require.LessOrEqual(t, len(got), hexPreviewLen*2+len("..."))
}

// --- Property tests: new implementations vs. the pre-fix reference -------

// numOldMakeScriptNumberDecode reproduces the pre-fix O(len(bb)^2) decode
// loop from MakeScriptNumber, kept here only as a reference for the
// equivalence property test below.
func numOldMakeScriptNumberDecode(bb []byte) *big.Int {
	v := new(big.Int)
	for i, b := range bb {
		v.Or(v, new(big.Int).Lsh(new(big.Int).SetBytes([]byte{b}), uint(8*i)))
	}
	if bb[len(bb)-1]&0x80 != 0 {
		shift := big.NewInt(int64(0x80))
		shift.Not(shift.Lsh(shift, uint(8*(len(bb)-1))))
		v.And(v, shift).Neg(v)
	}
	return v
}

// numOldBytes reproduces the pre-fix O(n^2) Bytes() encode loop, kept here
// only as a reference for the equivalence property test below.
func numOldBytes(n *ScriptNumber) []byte {
	if n.IsZero() {
		return []byte{}
	}
	isNegative := n.Val.Cmp(Zero) == -1
	if isNegative {
		n.Neg()
	}
	var bb []byte
	if !n.AfterGenesis {
		v := n.Val.Int64()
		if v > math.MaxInt32 {
			bb = big.NewInt(int64(math.MaxInt32)).Bytes()
		} else if v < math.MinInt32 {
			bb = big.NewInt(int64(math.MinInt32)).Bytes()
		}
	}
	if bb == nil {
		bb = n.Val.Bytes()
	}
	result := make([]byte, 0, len(bb)+1)
	cpy := new(big.Int).SetBytes(n.Val.Bytes())
	for cpy.Cmp(Zero) == 1 {
		result = append(result, byte(cpy.Int64()&0xff))
		cpy.Rsh(cpy, 8)
	}
	if result[len(result)-1]&0x80 != 0 {
		extraByte := byte(0x00)
		if isNegative {
			extraByte = 0x80
		}
		result = append(result, extraByte)
	} else if isNegative {
		result[len(result)-1] |= 0x80
	}
	return result
}

// TestGHSANumBytesMatchesOldImplementation proves the new linear Bytes() is
// byte-for-byte identical to the old quadratic implementation across random
// values (both positive and negative, spanning small and large magnitudes),
// as required before replacing it (GHSA-rh54-8fpg-8wwf).
func TestGHSANumBytesMatchesOldImplementation(t *testing.T) {
	t.Parallel()
	rnd := newNumRand(t)

	for i := 0; i < 20000; i++ {
		byteLen := rnd.Intn(600)
		mag := make([]byte, byteLen)
		rnd.Read(mag)
		v := new(big.Int).SetBytes(mag)
		if v.Sign() != 0 && rnd.Intn(2) == 0 {
			v.Neg(v)
		}

		for _, afterGenesis := range []bool{true, false} {
			got := (&ScriptNumber{Val: new(big.Int).Set(v), AfterGenesis: afterGenesis}).Bytes()
			want := numOldBytes(&ScriptNumber{Val: new(big.Int).Set(v), AfterGenesis: afterGenesis})
			require.Equal(t, want, got, "Bytes() mismatch for value %s (afterGenesis=%v)", v.String(), afterGenesis)
		}
	}
}

// TestGHSANumMakeScriptNumberDecodeMatchesOldImplementation proves the new
// linear decode loop inside MakeScriptNumber produces the same big.Int as
// the old quadratic per-byte Lsh/Or loop, for every input length including
// non-minimal encodings and negative zero.
func TestGHSANumMakeScriptNumberDecodeMatchesOldImplementation(t *testing.T) {
	t.Parallel()
	rnd := newNumRand(t)

	require.Zero(t, numOldMakeScriptNumberDecode([]byte{0x80}).Sign(), "sanity: old decode of negative zero is 0")

	for i := 0; i < 20000; i++ {
		n := 1 + rnd.Intn(600)
		bb := make([]byte, n)
		rnd.Read(bb)

		want := numOldMakeScriptNumberDecode(append([]byte(nil), bb...))
		got, err := MakeScriptNumber(bb, len(bb), false, true)
		require.NoError(t, err)
		require.Equal(t, 0, want.Cmp(got.Val), "decode mismatch for %x: old=%s new=%s", bb, want.String(), got.Val.String())
	}
}

// newNumRand returns a seeded math/rand source so property-test failures are
// reproducible; it does not need cryptographic randomness.
func newNumRand(t *testing.T) *deterministicRand {
	t.Helper()
	return newDeterministicRand(1)
}

// --- Benchmarks: linear vs. the old quadratic implementation --------------

func numBenchValue(byteLen int) *big.Int {
	mag := make([]byte, byteLen)
	for i := range mag {
		mag[i] = 0xfe
	}
	return new(big.Int).SetBytes(mag)
}

func BenchmarkGHSANumBytesNew1MB(b *testing.B) {
	numBenchmarkBytesNew(b, 1<<20)
}

func BenchmarkGHSANumBytesNew8MB(b *testing.B) {
	numBenchmarkBytesNew(b, 8<<20)
}

func BenchmarkGHSANumBytesNew32MB(b *testing.B) {
	numBenchmarkBytesNew(b, 32<<20)
}

func BenchmarkGHSANumBytesOld1MB(b *testing.B) {
	numBenchmarkBytesOld(b, 1<<20)
}

// BenchmarkGHSANumBytesOld8MB is intentionally NOT run by default (only via
// -bench, and even then it is slow: the old implementation is O(n^2), so an
// 8MB value takes tens of seconds). It exists purely to let a maintainer
// reproduce the before/after comparison.
func BenchmarkGHSANumBytesOld8MB(b *testing.B) {
	numBenchmarkBytesOld(b, 8<<20)
}

func numBenchmarkBytesNew(b *testing.B, byteLen int) {
	v := numBenchValue(byteLen)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n := &ScriptNumber{Val: new(big.Int).Set(v), AfterGenesis: true}
		_ = n.Bytes()
	}
}

func numBenchmarkBytesOld(b *testing.B, byteLen int) {
	v := numBenchValue(byteLen)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n := &ScriptNumber{Val: new(big.Int).Set(v), AfterGenesis: true}
		_ = numOldBytes(n)
	}
}

// deterministicRand is a tiny, dependency-free xorshift64* PRNG used only to
// make the property tests above reproducible without importing math/rand's
// global source (avoids any interaction with other tests' rand usage).
type deterministicRand struct {
	state uint64
}

func newDeterministicRand(seed uint64) *deterministicRand {
	if seed == 0 {
		seed = 1
	}
	return &deterministicRand{state: seed}
}

func (r *deterministicRand) next() uint64 {
	r.state ^= r.state << 13
	r.state ^= r.state >> 7
	r.state ^= r.state << 17
	return r.state
}

func (r *deterministicRand) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(r.next() % uint64(n)) //nolint:gosec // G115 -- n is always small and positive in this file
}

func (r *deterministicRand) Read(p []byte) {
	for i := 0; i < len(p); i += 8 {
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], r.next())
		copy(p[i:], buf[:])
	}
}
