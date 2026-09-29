// Copyright (c) 2024 The bsv-blockchain/go-sdk developers
// Use of this source code is governed by an ISC license that can be found in the LICENSE file.

// Tests derived from the BSV node v1.2.0 Chronicle upgrade functional tests:
// https://github.com/bitcoin-sv/bitcoin-sv/tree/172c8fa38cce30cf4df0327b33c7418ea6289de8/test/functional/chronicle_upgrade_tests

package interpreter

import (
	"math"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/errs"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// buildScript constructs a *script.Script from push-data + opcode sequences.
// Each element is either a []byte (pushed as data) or a byte (appended as opcode).
func buildScript(t *testing.T, parts ...interface{}) *script.Script {
	t.Helper()
	s := &script.Script{}
	for _, p := range parts {
		switch v := p.(type) {
		case byte:
			require.NoError(t, s.AppendOpcodes(v))
		case []byte:
			require.NoError(t, s.AppendPushData(v))
		default:
			t.Fatalf("buildScript: unsupported element type %T", p)
		}
	}
	return s
}

// chronicleVersionTx returns a minimal transaction with version 1.
// It is used for opcodes that read t.tx.Version (OP_VER, OP_VERIF, OP_VERNOTIF).
func chronicleVersionTx() *transaction.Transaction {
	s := script.Script{}
	return &transaction.Transaction{
		Version: 1,
		Inputs: []*transaction.TransactionInput{{
			SourceTxOutIndex: 0,
			UnlockingScript:  &s,
			SequenceNumber:   0xffffffff,
		}},
		Outputs: []*transaction.TransactionOutput{{
			Satoshis: 0,
		}},
	}
}

// versionLE serializes a uint32 as 4-byte little-endian – the format OP_VER pushes.
func versionLE(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)} //nolint:gosec // G115 -- intentional truncation to encode uint32 as little-endian bytes
}

// TestChronicleOpcodes_PreChronicle verifies that every Chronicle-reactivated opcode
// is rejected with the correct error when executed in the pre-Chronicle era.
// Mirrors the PRE_CHRONICLE phase in opcodes.py.
func TestChronicleOpcodesPreChronicle(t *testing.T) {
	t.Parallel()

	helloWorld := []byte("HelloWorld")
	oWorl := []byte("oWorl")
	hello := []byte("Hello")
	world := []byte("World")

	tests := []struct {
		name        string
		locking     func() *script.Script
		unlocking   *script.Script
		wantErrCode errs.ErrorCode
		flags       scriptflag.Flag
		needTx      bool // set true when the opcode reads t.tx
	}{
		// OP_VER (0x62) – reserved pre-Chronicle
		{
			name: "OP_VER OP_DROP OP_TRUE rejected pre-Chronicle",
			locking: func() *script.Script {
				return buildScript(t, script.OpVER, script.OpDROP, script.Op1)
			},
			unlocking:   &script.Script{},
			wantErrCode: errs.ErrReservedOpcode,
			needTx:      true,
		},
		// OP_VERIF (0x65) – always-illegal pre-Chronicle
		{
			name: "OP_VERIF always-illegal pre-Chronicle",
			locking: func() *script.Script {
				return buildScript(
					t,
					versionLE(1),
					script.OpVERIF,
					script.Op1,
					script.OpELSE,
					script.Op0,
					script.OpENDIF,
				)
			},
			unlocking:   &script.Script{},
			wantErrCode: errs.ErrReservedOpcode,
			needTx:      true,
		},
		// OP_VERNOTIF (0x66) – always-illegal pre-Chronicle
		{
			name: "OP_VERNOTIF always-illegal pre-Chronicle",
			locking: func() *script.Script {
				// 0x01ff0000 != version 1, so VERNOTIF branch would be true post-Chronicle
				return buildScript(
					t,
					versionLE(0x0000ff01),
					script.OpVERNOTIF,
					script.Op1,
					script.OpELSE,
					script.Op0,
					script.OpENDIF,
				)
			},
			unlocking:   &script.Script{},
			wantErrCode: errs.ErrReservedOpcode,
			needTx:      true,
		},
		// OP_SUBSTR (0xb3) – NOP4 pre-Chronicle; DiscourageUpgradableNops → error
		{
			name: "OP_SUBSTR treated as NOP4 pre-Chronicle",
			locking: func() *script.Script {
				return buildScript(
					t,
					helloWorld,
					script.Op4,
					script.Op5,
					script.OpSUBSTR,
					oWorl,
					script.OpEQUAL,
				)
			},
			unlocking:   &script.Script{},
			wantErrCode: errs.ErrDiscourageUpgradableNOPs,
			flags:       scriptflag.DiscourageUpgradableNops,
		},
		// OP_LEFT (0xb4) – NOP5 pre-Chronicle
		{
			name: "OP_LEFT treated as NOP5 pre-Chronicle",
			locking: func() *script.Script {
				return buildScript(
					t,
					helloWorld,
					script.Op5,
					script.OpLEFT,
					hello,
					script.OpEQUAL,
				)
			},
			unlocking:   &script.Script{},
			wantErrCode: errs.ErrDiscourageUpgradableNOPs,
			flags:       scriptflag.DiscourageUpgradableNops,
		},
		// OP_RIGHT (0xb5) – NOP6 pre-Chronicle
		{
			name: "OP_RIGHT treated as NOP6 pre-Chronicle",
			locking: func() *script.Script {
				return buildScript(
					t,
					helloWorld,
					script.Op5,
					script.OpRIGHT,
					world,
					script.OpEQUAL,
				)
			},
			unlocking:   &script.Script{},
			wantErrCode: errs.ErrDiscourageUpgradableNOPs,
			flags:       scriptflag.DiscourageUpgradableNops,
		},
		// OP_2MUL (0x8d) – disabled pre-Chronicle
		{
			name: "OP_2MUL disabled pre-Chronicle",
			locking: func() *script.Script {
				return buildScript(t, script.Op1, script.Op2MUL, script.Op2, script.OpEQUAL)
			},
			unlocking:   &script.Script{},
			wantErrCode: errs.ErrDisabledOpcode,
		},
		// OP_2DIV (0x8e) – disabled pre-Chronicle
		{
			name: "OP_2DIV disabled pre-Chronicle",
			locking: func() *script.Script {
				return buildScript(t, script.Op2, script.Op2DIV, script.Op1, script.OpEQUAL)
			},
			unlocking:   &script.Script{},
			wantErrCode: errs.ErrDisabledOpcode,
		},
		// OP_LSHIFTNUM (0xb6) – NOP7 pre-Chronicle
		{
			name: "OP_LSHIFTNUM treated as NOP7 pre-Chronicle",
			locking: func() *script.Script {
				return buildScript(t, script.Op1, script.Op2, script.OpLSHIFTNUM, script.Op4, script.OpEQUAL)
			},
			unlocking:   &script.Script{},
			wantErrCode: errs.ErrDiscourageUpgradableNOPs,
			flags:       scriptflag.DiscourageUpgradableNops,
		},
		// OP_RSHIFTNUM (0xb7) – NOP8 pre-Chronicle
		{
			name: "OP_RSHIFTNUM treated as NOP8 pre-Chronicle",
			locking: func() *script.Script {
				return buildScript(t, script.Op16, script.Op2, script.OpRSHIFTNUM, script.Op4, script.OpEQUAL)
			},
			unlocking:   &script.Script{},
			wantErrCode: errs.ErrDiscourageUpgradableNOPs,
			flags:       scriptflag.DiscourageUpgradableNops,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			locking := tc.locking()
			opts := []ExecutionOptionFunc{
				WithScripts(locking, tc.unlocking),
				WithAfterGenesis(),
			}
			if tc.flags != 0 {
				opts = append(opts, WithFlags(tc.flags))
			}
			if tc.needTx {
				tx := chronicleVersionTx()
				prevOut := &transaction.TransactionOutput{LockingScript: locking}
				opts = []ExecutionOptionFunc{
					WithTx(tx, 0, prevOut),
					WithAfterGenesis(),
				}
				if tc.flags != 0 {
					opts = append(opts, WithFlags(tc.flags))
				}
			}

			err := NewEngine().Execute(opts...)
			require.Error(t, err)
			var scriptErr errs.Error
			require.ErrorAs(t, err, &scriptErr)
			require.Equal(t, tc.wantErrCode, scriptErr.ErrorCode,
				"expected error code %s got %s", tc.wantErrCode, scriptErr.ErrorCode)
		})
	}
}

// TestChronicleOpcodes_PostChronicle verifies that every Chronicle-reactivated opcode
// executes correctly in the post-Chronicle era.
// Mirrors the POST_CHRONICLE phase in opcodes.py.
func TestChronicleOpcodesPostChronicle(t *testing.T) {
	t.Parallel()

	helloWorld := []byte("HelloWorld")
	oWorl := []byte("oWorl")
	hello := []byte("Hello")
	world := []byte("World")

	tests := []struct {
		name      string
		locking   func() *script.Script
		unlocking *script.Script
		needTx    bool
	}{
		// OP_VER pushes tx version (1 → 01 00 00 00), OP_DROP, OP_TRUE → succeeds
		{
			name: "OP_VER pushes version, OP_DROP, OP_TRUE succeeds post-Chronicle",
			locking: func() *script.Script {
				return buildScript(t, script.OpVER, script.OpDROP, script.Op1)
			},
			unlocking: &script.Script{},
			needTx:    true,
		},
		// OP_VERIF with matching version: conditional true branch → OP_TRUE
		{
			name: "OP_VERIF version-conditional true branch post-Chronicle",
			locking: func() *script.Script {
				return buildScript(
					t,
					versionLE(1), // push 01 00 00 00 (version 1 LE)
					script.OpVERIF,
					script.Op1,
					script.OpELSE,
					script.Op0,
					script.OpENDIF,
				)
			},
			unlocking: &script.Script{},
			needTx:    true,
		},
		// OP_VERNOTIF with non-matching version: NOTIF branch (true when not equal) → OP_TRUE
		{
			name: "OP_VERNOTIF version-conditional (not-equal branch) post-Chronicle",
			locking: func() *script.Script {
				// 0x0000ff01 ≠ version 1 (0x00000001), so VERNOTIF takes the true branch
				return buildScript(
					t,
					versionLE(0x0000ff01),
					script.OpVERNOTIF,
					script.Op1,
					script.OpELSE,
					script.Op0,
					script.OpENDIF,
				)
			},
			unlocking: &script.Script{},
			needTx:    true,
		},
		// OP_SUBSTR("HelloWorld", 4, 5) == "oWorl"
		{
			name: "OP_SUBSTR extracts substring post-Chronicle",
			locking: func() *script.Script {
				return buildScript(
					t,
					helloWorld,
					script.Op4,
					script.Op5,
					script.OpSUBSTR,
					oWorl,
					script.OpEQUAL,
				)
			},
			unlocking: &script.Script{},
		},
		// OP_LEFT("HelloWorld", 5) == "Hello"
		{
			name: "OP_LEFT returns left N bytes post-Chronicle",
			locking: func() *script.Script {
				return buildScript(
					t,
					helloWorld,
					script.Op5,
					script.OpLEFT,
					hello,
					script.OpEQUAL,
				)
			},
			unlocking: &script.Script{},
		},
		// OP_RIGHT("HelloWorld", 5) == "World"
		{
			name: "OP_RIGHT returns right N bytes post-Chronicle",
			locking: func() *script.Script {
				return buildScript(
					t,
					helloWorld,
					script.Op5,
					script.OpRIGHT,
					world,
					script.OpEQUAL,
				)
			},
			unlocking: &script.Script{},
		},
		// OP_2MUL: 1 * 2 == 2
		{
			name: "OP_2MUL multiplies by 2 post-Chronicle",
			locking: func() *script.Script {
				return buildScript(t, script.Op1, script.Op2MUL, script.Op2, script.OpEQUAL)
			},
			unlocking: &script.Script{},
		},
		// OP_2DIV: 2 / 2 == 1
		{
			name: "OP_2DIV divides by 2 post-Chronicle",
			locking: func() *script.Script {
				return buildScript(t, script.Op2, script.Op2DIV, script.Op1, script.OpEQUAL)
			},
			unlocking: &script.Script{},
		},
		// OP_LSHIFTNUM: 1 << 2 == 4
		{
			name: "OP_LSHIFTNUM left-shifts by N post-Chronicle",
			locking: func() *script.Script {
				return buildScript(t, script.Op1, script.Op2, script.OpLSHIFTNUM, script.Op4, script.OpEQUAL)
			},
			unlocking: &script.Script{},
		},
		// OP_RSHIFTNUM: 16 >> 2 == 4
		{
			name: "OP_RSHIFTNUM right-shifts by N post-Chronicle",
			locking: func() *script.Script {
				return buildScript(t, script.Op16, script.Op2, script.OpRSHIFTNUM, script.Op4, script.OpEQUAL)
			},
			unlocking: &script.Script{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			locking := tc.locking()
			var opts []ExecutionOptionFunc
			if tc.needTx {
				prevOut := &transaction.TransactionOutput{LockingScript: locking}
				opts = []ExecutionOptionFunc{
					WithTx(chronicleVersionTx(), 0, prevOut),
					WithAfterChronicle(),
				}
			} else {
				opts = []ExecutionOptionFunc{
					WithScripts(locking, tc.unlocking),
					WithAfterChronicle(),
				}
			}

			err := NewEngine().Execute(opts...)
			require.NoError(t, err)
		})
	}
}

// TestChronicleOpcodes_EdgeCases covers boundary conditions for Chronicle opcodes.
func TestChronicleOpcodesEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("OP_VER without tx returns error post-Chronicle", func(t *testing.T) {
		t.Parallel()
		locking := buildScript(t, script.OpVER, script.Op1)
		err := NewEngine().Execute(
			WithScripts(locking, &script.Script{}),
			WithAfterChronicle(),
		)
		require.Error(t, err)
	})

	t.Run("OP_SUBSTR invalid range rejected post-Chronicle", func(t *testing.T) {
		t.Parallel()
		// "Hi" has length 2; requesting begin=5, len=1 is out of range
		locking := buildScript(
			t,
			[]byte("Hi"),
			script.Op5,
			script.Op1,
			script.OpSUBSTR,
			script.Op1, // bogus expected
			script.OpEQUAL,
		)
		err := NewEngine().Execute(
			WithScripts(locking, &script.Script{}),
			WithAfterChronicle(),
		)
		require.Error(t, err)
	})

	t.Run("OP_LEFT zero bytes post-Chronicle", func(t *testing.T) {
		t.Parallel()
		// OP_LEFT("Hello", 0) == ""
		locking := buildScript(
			t,
			[]byte("Hello"),
			script.Op0,
			script.OpLEFT,
			[]byte{}, // push empty
			script.OpEQUAL,
		)
		err := NewEngine().Execute(
			WithScripts(locking, &script.Script{}),
			WithAfterChronicle(),
		)
		require.NoError(t, err)
	})

	t.Run("OP_RIGHT full-length post-Chronicle", func(t *testing.T) {
		t.Parallel()
		// OP_RIGHT("Hello", 5) == "Hello" (all bytes)
		locking := buildScript(
			t,
			[]byte("Hello"),
			script.Op5,
			script.OpRIGHT,
			[]byte("Hello"),
			script.OpEQUAL,
		)
		err := NewEngine().Execute(
			WithScripts(locking, &script.Script{}),
			WithAfterChronicle(),
		)
		require.NoError(t, err)
	})

	t.Run("OP_LSHIFTNUM zero shift is identity post-Chronicle", func(t *testing.T) {
		t.Parallel()
		// 7 << 0 == 7
		locking := buildScript(
			t,
			script.Op7,
			script.Op0,
			script.OpLSHIFTNUM,
			script.Op7,
			script.OpEQUAL,
		)
		err := NewEngine().Execute(
			WithScripts(locking, &script.Script{}),
			WithAfterChronicle(),
		)
		require.NoError(t, err)
	})

	t.Run("OP_RSHIFTNUM to zero post-Chronicle", func(t *testing.T) {
		t.Parallel()
		// 1 >> 8 == 0
		locking := buildScript(
			t,
			script.Op1,
			script.Op8,
			script.OpRSHIFTNUM,
			script.Op0,
			script.OpEQUAL,
		)
		err := NewEngine().Execute(
			WithScripts(locking, &script.Script{}),
			WithAfterChronicle(),
		)
		require.NoError(t, err)
	})

	t.Run("OP_2MUL zero post-Chronicle", func(t *testing.T) {
		t.Parallel()
		// 0 * 2 == 0
		locking := buildScript(
			t,
			script.Op0,
			script.Op2MUL,
			script.Op0,
			script.OpEQUAL,
		)
		err := NewEngine().Execute(
			WithScripts(locking, &script.Script{}),
			WithAfterChronicle(),
		)
		require.NoError(t, err)
	})

	t.Run("OP_VERIF non-matching version takes else branch post-Chronicle", func(t *testing.T) {
		t.Parallel()
		// Push version 2 bytes; tx is version 1 → not equal → VERIF goes to ELSE → OP_TRUE
		locking := buildScript(
			t,
			versionLE(2), // 02 00 00 00
			script.OpVERIF,
			script.Op0, // true branch (NOT taken since versions differ)
			script.OpELSE,
			script.Op1, // false branch (taken)
			script.OpENDIF,
		)
		tx := chronicleVersionTx()
		prevOut := &transaction.TransactionOutput{LockingScript: locking}
		err := NewEngine().Execute(
			WithTx(tx, 0, prevOut),
			WithAfterChronicle(),
		)
		require.NoError(t, err)
	})

	t.Run("OP_VERNOTIF matching version takes else branch post-Chronicle", func(t *testing.T) {
		t.Parallel()
		// Push version 1 bytes; tx is version 1 → equal → VERNOTIF (not-if) goes to ELSE → OP_TRUE
		locking := buildScript(
			t,
			versionLE(1), // 01 00 00 00
			script.OpVERNOTIF,
			script.Op0, // true branch (NOT taken since they are equal)
			script.OpELSE,
			script.Op1, // false branch (taken because VERNOTIF condition is "not equal")
			script.OpENDIF,
		)
		tx := chronicleVersionTx()
		prevOut := &transaction.TransactionOutput{LockingScript: locking}
		err := NewEngine().Execute(
			WithTx(tx, 0, prevOut),
			WithAfterChronicle(),
		)
		require.NoError(t, err)
	})

	t.Run("MaxScriptNumberLength is 32MB post-Chronicle", func(t *testing.T) {
		t.Parallel()
		cfg := &afterChronicleConfig{}
		require.Equal(t, MaxScriptNumberLengthAfterChronicle, cfg.MaxScriptNumberLength())
		require.Equal(t, 32*1024*1024, cfg.MaxScriptNumberLength())
	})

	t.Run("afterChronicleConfig implies afterGenesis", func(t *testing.T) {
		t.Parallel()
		cfg := &afterChronicleConfig{}
		require.True(t, cfg.AfterGenesis())
		require.True(t, cfg.AfterChronicle())
	})
}

// TestChronicleNopBehavior_WithoutDiscourageFlag verifies that the Chronicle NOP-type
// opcodes (SUBSTR/LEFT/RIGHT/LSHIFTNUM/RSHIFTNUM) are silent NOPs pre-Chronicle when
// the DiscourageUpgradableNops flag is absent, leaving extra items on the stack.
func TestChronicleNopBehaviorWithoutDiscourageFlag(t *testing.T) {
	t.Parallel()

	// Pre-Chronicle: OP_SUBSTR is a NOP, so stack ends up with extra items.
	// Script: "AB" OP_1 OP_1 OP_SUBSTR "AB" OP_EQUAL
	// Stack after NOP:  ["AB", 1, 1, "AB"] → EQUAL pops "AB"==1 → false
	// Top of stack is false → ErrEvalFalse (or the equal gives false)
	t.Run("OP_SUBSTR as silent NOP leaves extra stack items", func(t *testing.T) {
		t.Parallel()
		locking := buildScript(
			t,
			[]byte("AB"),
			script.Op1,
			script.Op1,
			script.OpSUBSTR, // NOP, does nothing
			[]byte("AB"),    // pushed on top
			script.OpEQUAL,  // "AB" == 1? → false, leaves extra ["AB",1,false]
		)
		err := NewEngine().Execute(
			WithScripts(locking, &script.Script{}),
			WithAfterGenesis(),
			// no DiscourageUpgradableNops
		)
		// Script ends with false top of stack (or false-equal) – must fail
		require.Error(t, err)
	})
}

// shiftNumPush returns the minimal script number encoding of v as a buildScript
// element (OP_0 for zero).
func shiftNumPush(v *big.Int) interface{} {
	b := (&ScriptNumber{Val: v, AfterGenesis: true}).Bytes()
	if len(b) == 0 {
		return script.Op0
	}
	return b
}

// TestChronicleShiftNumNodeSemantics pins OP_LSHIFTNUM / OP_RSHIFTNUM to the
// SV Node reference implementation (bitcoin-sv src/script/interpreter.cpp,
// CScriptNum::operator<<= / operator>>= in src/script/script_num.cpp, and
// bsv::bint in src/big_int.cpp, backed by OpenSSL BN_lshift / BN_rshift).
// The shift acts on the magnitude and keeps the sign, so a right shift of a
// negative number truncates toward zero; the expected values mirror
// bitcoin-sv src/test/lrshiftnum_tests.cpp where it has them.
func TestChronicleShiftNumNodeSemantics(t *testing.T) {
	t.Parallel()

	maxLen := MaxScriptNumberLengthAfterChronicle
	pow2 := func(n uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), n) }

	type tc struct {
		name     string
		value    *big.Int
		shift    *big.Int
		right    bool
		expected *big.Int // nil when the script must fail
		errCode  errs.ErrorCode
	}
	i := big.NewInt
	tests := []tc{
		// OP_RSHIFTNUM: truncation toward zero for negatives.
		{name: "-1 >> 1 == 0", value: i(-1), shift: i(1), right: true, expected: i(0)},
		{name: "-5 >> 1 == -2", value: i(-5), shift: i(1), right: true, expected: i(-2)},
		{name: "-17 >> 2 == -4", value: i(-17), shift: i(2), right: true, expected: i(-4)},
		{name: "-16 >> 2 == -4", value: i(-16), shift: i(2), right: true, expected: i(-4)},
		{name: "-256 >> 1 == -128", value: i(-256), shift: i(1), right: true, expected: i(-128)},
		{name: "-7 >> 300 == 0", value: i(-7), shift: i(300), right: true, expected: i(0)},
		{
			name:     "-(2^100+5) >> 99 == -2",
			value:    new(big.Int).Neg(new(big.Int).Add(pow2(100), i(5))),
			shift:    i(99),
			right:    true,
			expected: i(-2),
		},
		{name: "5 >> 1 == 2", value: i(5), shift: i(1), right: true, expected: i(2)},
		{name: "1 >> 1 == 0", value: i(1), shift: i(1), right: true, expected: i(0)},
		{name: "-5 >> 0 == -5", value: i(-5), shift: i(0), right: true, expected: i(-5)},
		{name: "-5 >> INT_MAX == 0", value: i(-5), shift: i(math.MaxInt32), right: true, expected: i(0)},
		{
			name: "shift above INT_MAX fails", value: i(-5), shift: i(math.MaxInt32 + 1), right: true,
			errCode: errs.ErrNumberTooBig,
		},
		{
			name: "shift of 2^64+1 fails", value: i(5), shift: new(big.Int).Add(pow2(64), i(1)), right: true,
			errCode: errs.ErrNumberTooBig,
		},
		{name: "negative right shift count fails", value: i(5), shift: i(-1), right: true, errCode: errs.ErrNumberTooSmall},

		// OP_LSHIFTNUM: exact multiplication by 2^n, sign kept.
		{name: "-1 << 7 == -128", value: i(-1), shift: i(7), expected: i(-128)},
		{name: "-5 << 1 == -10", value: i(-5), shift: i(1), expected: i(-10)},
		{name: "-3 << 100", value: i(-3), shift: i(100), expected: new(big.Int).Neg(new(big.Int).Mul(i(3), pow2(100)))},
		{name: "0 << 8*maxLen == 0", value: i(0), shift: i(int64(8 * maxLen)), expected: i(0)},
		{
			name: "0 << 8*(maxLen+1) overflows", value: i(0), shift: i(int64(8 * (maxLen + 1))),
			errCode: errs.ErrNumberTooBig,
		},
		{
			name: "1 << 8*maxLen overflows", value: i(1), shift: i(int64(8 * maxLen)),
			errCode: errs.ErrNumberTooBig,
		},
		{
			// 0x40 << 8*(maxLen-1)+1 needs maxLen+1 bytes (sign byte).
			name: "result one byte too long overflows", value: i(0x40), shift: i(int64(8*(maxLen-1) + 1)),
			errCode: errs.ErrNumberTooBig,
		},
		{
			name: "shift of 2^64+1 overflows", value: i(5), shift: new(big.Int).Add(pow2(64), i(1)),
			errCode: errs.ErrNumberTooBig,
		},
		{name: "negative left shift count fails", value: i(5), shift: i(-1), errCode: errs.ErrNumberTooSmall},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			op := script.OpLSHIFTNUM
			if tt.right {
				op = script.OpRSHIFTNUM
			}
			parts := []interface{}{shiftNumPush(tt.value), shiftNumPush(tt.shift), op}
			if tt.expected != nil {
				parts = append(parts, shiftNumPush(tt.expected), script.OpEQUAL)
			}
			err := NewEngine().Execute(
				WithScripts(buildScript(t, parts...), &script.Script{}),
				WithAfterChronicle(),
			)
			if tt.expected != nil {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.True(t, errs.IsErrorCode(err, tt.errCode), "unexpected error: %v", err)
		})
	}
}

func TestScriptNumEncodedLen(t *testing.T) {
	t.Parallel()
	for _, v := range []int64{0, 1, -1, 0x7f, -0x7f, 0x80, -0x80, 0xff, 0x7fff, 0x8000, -0x8000, math.MaxInt64, math.MinInt64 + 1} {
		n := big.NewInt(v)
		require.Len(t, (&ScriptNumber{Val: n, AfterGenesis: true}).Bytes(), scriptNumEncodedLen(n), "value %d", v)
	}
}
