// Copyright (c) 2025 The bsv-blockchain/go-sdk developers
// Use of this source code is governed by an ISC license that can be found in the LICENSE file.

// Further regression tests for the numeric-opcode area of
// GHSA-rh54-8fpg-8wwf: the compiled node's OP_SUBSTR/OP_LEFT/OP_RIGHT
// legacy operand decode, OP_LSHIFTNUM/OP_RSHIFTNUM check order and exact
// post-shift size check, OpenSSL BN_mul's working-size limit in OP_MUL, and
// OP_NUM2BIN padding. Every entry of num2OracleVectors was run through the
// real bitcoin-sv node (gobdk v1.2.4, bitcoin-sv 879fc8b42) under the
// recorded node flag word; the expected verdict is the node's. Helper names
// are prefixed with "num2".
package interpreter

import (
	"encoding/hex"
	"math"
	"math/big"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/errs"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// The spending transactions the vectors were checked with: a single input
// with an empty unlocking script and one 1-sat OP_1 output (version 1 and
// version 2); the seed-42 sweep case carries its own transaction.
const (
	num2TxV1 = "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000000ffffffff010100000000000000015100000000"
	num2TxV2 = "020000000144444444444444444444444444444444444444444444444444444444444444440000000000ffffffff010100000000000000015100000000"
)

// num2Vector is one case verified against bitcoin-sv (GoBDK): a spending tx,
// the locking script of its single previous output, the node flag word it
// was judged under and the node's verdict.
type num2Vector struct {
	name  string
	word  uint32
	tx    string
	lock  string
	valid bool
	heavy bool // builds multi-megabyte numbers; skipped under -short
}

// num2Flags maps a node script-verify flag word onto scriptflag.Flag bit by
// bit, as when the vectors were verified against bitcoin-sv (GoBDK).
func num2Flags(word uint32) scriptflag.Flag {
	nodeToSDK := map[uint32]scriptflag.Flag{
		1 << 0:  scriptflag.Bip16,
		1 << 1:  scriptflag.VerifyStrictEncoding,
		1 << 2:  scriptflag.VerifyDERSignatures,
		1 << 3:  scriptflag.VerifyLowS,
		1 << 4:  scriptflag.StrictMultiSig,
		1 << 5:  scriptflag.VerifySigPushOnly,
		1 << 6:  scriptflag.VerifyMinimalData,
		1 << 7:  scriptflag.DiscourageUpgradableNops,
		1 << 8:  scriptflag.VerifyCleanStack,
		1 << 9:  scriptflag.VerifyCheckLockTimeVerify,
		1 << 10: scriptflag.VerifyCheckSequenceVerify,
		1 << 13: scriptflag.VerifyMinimalIf,
		1 << 14: scriptflag.VerifyNullFail,
		1 << 16: scriptflag.EnableSighashForkID,
		1 << 18: scriptflag.Genesis,
		1 << 19: scriptflag.UTXOAfterGenesis,
		1 << 20: scriptflag.Chronicle,
		1 << 21: scriptflag.UTXOAfterChronicle,
	}
	var f scriptflag.Flag
	for bit, flag := range nodeToSDK {
		if word&bit != 0 {
			f |= flag
		}
	}
	return f
}

// num2Exec executes every input of txHex against lockHex (as each input's
// previous output) under the node flag word, as when the vectors were
// verified against bitcoin-sv (GoBDK).
func num2Exec(t *testing.T, txHex, lockHex string, word uint32) error {
	t.Helper()
	tx, err := transaction.NewTransactionFromHex(txHex)
	require.NoError(t, err)
	lock, err := hex.DecodeString(lockHex)
	require.NoError(t, err)
	for i, in := range tx.Inputs {
		prev := &transaction.TransactionOutput{LockingScript: script.NewFromBytes(lock), Satoshis: 1000}
		in.SetSourceTxOutput(prev)
		if err := NewEngine().Execute(WithTx(tx, i, prev), WithFlags(num2Flags(word))); err != nil {
			return err
		}
	}
	return nil
}

// TestGHSANum2OracleVectors replays the vectors verified against bitcoin-sv
// (GoBDK): OP_SUBSTR/OP_LEFT/OP_RIGHT operands of 9 to 1000 bytes,
// OP_LSHIFTNUM/OP_RSHIFTNUM at the 32,000,000-byte boundary, the seed-42
// index-3094 sweep case, OP_MUL at OpenSSL's BN_mul limit, OP_NUM2BIN outputs
// and 1-9 MB operands for every big-number arithmetic opcode. Valid
// large-operand and NUM2BIN vectors pin the exact result with OP_SHA256
// <digest> OP_EQUAL.
func TestGHSANum2OracleVectors(t *testing.T) {
	for _, v := range num2OracleVectors {
		t.Run(v.name, func(t *testing.T) {
			if v.heavy && testing.Short() {
				t.Skip("builds multi-megabyte script numbers")
			}
			err := num2Exec(t, v.tx, v.lock, v.word)
			if v.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

// TestGHSANum2ErrorClasses checks that the SDK fails these vectors in the
// same error class as the node (whose message is quoted per case), i.e.
// that the checks run in node's order.
func TestGHSANum2ErrorClasses(t *testing.T) {
	for _, tt := range []struct {
		name  string
		lock  string
		want  errs.ErrorCode
		heavy bool
	}{
		// "Script number overflow": the width pre-check rejects n > INT_MAX.
		{"LSHIFTNUM OP_0 <2^31>", "00050000008000b67551", errs.ErrNumberTooBig, false},
		// "Big integer OpenSSL error".
		{"RSHIFTNUM OP_0 <2^31>", "00050000008000b77551", errs.ErrBigInt, false},
		// "Script number overflow": the value decode fails before the INT_MAX check.
		{"RSHIFTNUM <32,000,001-byte value> <2^31>", "51040148e80180050000008000b77551", errs.ErrNumberTooBig, true},
		// "Script number overflow": the exact post-shift check.
		{"LSHIFTNUM OP_1 <255999999>", "5104ff3f420fb67551", errs.ErrNumberTooBig, true},
		// "Big integer OpenSSL error": 1,048,577 x 1,048,577 words.
		{"MUL at the BN_mul limit", "0004000080008001017e0004000080008001017e957551", errs.ErrBigInt, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.heavy && testing.Short() {
				t.Skip("builds multi-megabyte script numbers")
			}
			err := num2Exec(t, num2TxV1, tt.lock, 0x3d462f)
			require.True(t, errs.IsErrorCode(err, tt.want), "got %v, want code %v", err, tt.want)
		})
	}
}

// TestGHSANum2LegacyDeserializeInt64 pins the compiled node's legacy decode
// for 9+ byte operands: byte i is ORed into byte slot i%8 and the last byte
// is dropped. Each shape is covered by a vector verified against bitcoin-sv
// (GoBDK) above (the "legacy operand" entries).
func TestGHSANum2LegacyDeserializeInt64(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int64
	}{
		{"9 byte: bytes 0-7 raw, last byte dropped", "0102030405060708" + "ff", 0x0807060504030201},
		{"10 byte: byte 8 folds into slot 0", "0400000000000000" + "40" + "00", 0x44},
		{"10 byte: bytes 0-7 zero, byte 8 alone", "0000000000000000" + "04" + "00", 4},
		{"17 byte: byte 15 lands in slot 7", "04" + "0000000000000000000000000000" + "10" + "00", 0x1000000000000004},
		{"17 byte: sign bit via slot 7 gives a negative int64", "04000000000000000000000000000080" + "00", math.MinInt64 | 4},
		{"33 byte: slots 0 and 1 accumulate across periods", "01000000000000000200000000000000" + "0001000000000000" + "0000000000000000" + "80", 0x103},
		{"last byte never contributes", "0000000000000000" + "0000000000000000" + "7f", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in, err := hex.DecodeString(tt.in)
			require.NoError(t, err)
			require.Equal(t, tt.want, legacyDeserializeInt64(in))
		})
	}

	t.Run("linear in operand size", func(t *testing.T) {
		if testing.Short() {
			t.Skip("allocates a 32,000,000-byte operand")
		}
		in := make([]byte, 32_000_000)
		in[8*1_000_000] = 0x05
		require.Equal(t, int64(5), legacyDeserializeInt64(in))
	})
}

// num2NewStack builds a bare post-Genesis *stack for calling stack methods
// directly.
func num2NewStack(maxLen int) *stack {
	return &stack{
		maxNumLength: maxLen,
		afterGenesis: true,
		debug:        &nopDebugger{},
		sh:           &nopStateHandler{},
	}
}

// TestGHSANum2PopLegacyIntSaturates checks the getint() int32 saturation
// that node applies before OP_SUBSTR/OP_LEFT/OP_RIGHT's range checks.
func TestGHSANum2PopLegacyIntSaturates(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want int32
	}{
		{"0000000001000000" + "00", math.MaxInt32}, // raw 2^32
		{"ffffff7f00000000" + "00", math.MaxInt32}, // raw MaxInt32, unchanged
		{"ffffffffffffffff" + "00", -1},            // raw -1, unchanged
		{"0000000000000080" + "00", math.MinInt32}, // raw MinInt64
		{"0100000080", -1},                         // 5-byte sign-magnitude -1
		{"ffffffff80", math.MinInt32},              // 5-byte -(2^32-1)
	} {
		in, err := hex.DecodeString(tt.in)
		require.NoError(t, err)
		s := num2NewStack(MaxScriptNumberLengthAfterChronicle)
		s.PushByteArray(in)
		got, err := s.PopLegacyInt()
		require.NoError(t, err)
		require.Equal(t, tt.want, got, tt.in)
	}
}

// TestGHSANum2SerializedSize checks serializedSize against the length of
// the real encoding.
func TestGHSANum2SerializedSize(t *testing.T) {
	r := rand.New(rand.NewSource(1)) //nolint:gosec // deterministic test input
	vals := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(-1), big.NewInt(127), big.NewInt(128), big.NewInt(-128), big.NewInt(255), big.NewInt(256)}
	for i := 0; i < 500; i++ {
		b := make([]byte, r.Intn(40))
		_, _ = r.Read(b)
		v := new(big.Int).SetBytes(b)
		if r.Intn(2) == 0 {
			v.Neg(v)
		}
		vals = append(vals, v)
	}
	for _, v := range vals {
		want := len((&ScriptNumber{Val: new(big.Int).Set(v)}).Bytes())
		require.Equal(t, want, serializedSize(v), v.String())
	}
}

// TestGHSANum2BnMulFails pins the OpenSSL BN_mul working-size rule at its
// boundaries (operand sizes in 64-bit words). Every shape except the
// word-count gap of 2 at 1,048,577 words is also a "BN_mul limit" node
// vector; that one is not, because the node multiplies it with a quadratic
// schoolbook loop that takes too long to run.
func TestGHSANum2BnMulFails(t *testing.T) {
	words := func(w int) *big.Int { return new(big.Int).Lsh(big.NewInt(1), uint(64*(w-1))) }
	for _, tt := range []struct {
		al, bl int
		fails  bool
	}{
		{1048576, 1048576, false},
		{1048576, 1048575, false},
		{1048575, 1048576, false},
		{1048577, 1048576, true},
		{1048576, 1048577, true},
		{1048577, 1048577, true},
		{1048578, 1048577, true},
		{1500000, 1500001, true},
		{2000000, 1999999, true},
		{2000000, 2000000, true},
		{1048577, 1048575, false}, // |al-bl| = 2: schoolbook path
		{1048577, 16, false},
		{1048577, 15, false},
		{16, 16, false},
		{0, 2000000, false},
	} {
		a, b := new(big.Int), new(big.Int)
		if tt.al > 0 {
			a = words(tt.al)
		}
		if tt.bl > 0 {
			b = words(tt.bl)
		}
		require.Equal(t, tt.fails, bnMulFails(a, b), "%d x %d words", tt.al, tt.bl)
		require.Equal(t, tt.fails, bnMulFails(new(big.Int).Neg(a), b), "-%d x %d words", tt.al, tt.bl)
	}
}

// num2OldNum2binPad is the pre-change OP_NUM2BIN padding loop, kept as the
// reference for TestGHSANum2Num2binPadding.
func num2OldNum2binPad(b []byte, n int) []byte {
	signbit := byte(0x00)
	if len(b) > 0 {
		signbit = b[len(b)-1] & 0x80
		b[len(b)-1] &= 0x7f
	}
	for n > len(b)+1 {
		b = append(b, 0x00)
	}
	return append(b, signbit)
}

// TestGHSANum2Num2binPadding checks that OP_NUM2BIN's single-allocation
// padding produces the same bytes as the old append loop.
func TestGHSANum2Num2binPadding(t *testing.T) {
	r := rand.New(rand.NewSource(2)) //nolint:gosec // deterministic test input
	for i := 0; i < 300; i++ {
		a := make([]byte, r.Intn(8))
		_, _ = r.Read(a)
		sn, err := MakeScriptNumber(a, len(a), false, true)
		require.NoError(t, err)
		minimal := sn.Bytes()
		n := len(minimal) + 1 + r.Intn(40)
		want := num2OldNum2binPad(append([]byte{}, minimal...), n)

		lock := &script.Script{}
		require.NoError(t, lock.AppendPushData(a))
		require.NoError(t, lock.AppendPushData((&ScriptNumber{Val: big.NewInt(int64(n))}).Bytes()))
		require.NoError(t, lock.AppendOpcodes(script.OpNUM2BIN))
		require.NoError(t, lock.AppendPushData(want))
		require.NoError(t, lock.AppendOpcodes(script.OpEQUAL))
		require.NoError(t, num2Exec(t, num2TxV1, hex.EncodeToString(*lock), 0x3d462f), "a=%x n=%d", a, n)
	}
}

// num2OracleVectors holds the vectors verified against bitcoin-sv (GoBDK)
// that TestGHSANum2OracleVectors replays: {name, node flag word, tx, lock,
// node verdict, heavy}.
var num2OracleVectors = []num2Vector{
	{"legacy operand decode: OP_LEFT 10-byte len 04 00x7 40 00 on 20 bytes (mod-64: 4|64=68 -> invalid; ignore-tail: 4 -> valid)", 0x3d462f, num2TxV1, "14000102030405060708090a0b0c0d0e0f101112130a04000000000000004000b47551", false, false},
	{"legacy operand decode: OP_LEFT 10-byte len 00x8 04 00 then EQUAL 4-byte prefix (mod-64: LEFT 4 -> valid; ignore-tail: LEFT 0 -> invalid)", 0x3d462f, num2TxV1, "14000102030405060708090a0b0c0d0e0f101112130a00000000000000000400b4040001020387", true, false},
	{"legacy operand decode: OP_LEFT 17-byte len 04 00x14 10 00 (byte15<<56 -> huge -> invalid under mod-64; ignore-tail: 4 -> valid)", 0x3d462f, num2TxV1, "14000102030405060708090a0b0c0d0e0f10111213110400000000000000000000000000001000b47551", false, false},
	{"legacy operand decode: OP_SUBSTR begin 9-byte 00x8 80 (=-0 as 9 bytes: ignore-tail gives 0), len 4, EQUAL prefix", 0x3d462f, num2TxV1, "14000102030405060708090a0b0c0d0e0f101112130900000000000000008054b3040001020387", true, false},
	{"shift size check: OP_0 2147483647 OP_LSHIFTNUM OP_DROP OP_1", 0x3d462f, num2TxV1, "0004ffffff7fb67551", false, false},
	{"shift size check: OP_0 <255999999> LSHIFTNUM (size(0)+31,999,999 <= 32M?)", 0x3d462f, num2TxV1, "0004ff3f420fb67551", true, false},
	{"shift size check: OP_0 <256000000> LSHIFTNUM (0 + 32,000,000 bytes == limit)", 0x3d462f, num2TxV1, "00040040420fb67551", true, false},
	{"shift size check: OP_1 <255999992> LSHIFTNUM (1+31,999,999=32M; result 32,000,000 bytes top 0x01)", 0x3d462f, num2TxV1, "5104f83f420fb67551", true, true},
	{"shift size check: OP_1 <255999998> LSHIFTNUM (result top byte 0x40, 32,000,000 bytes)", 0x3d462f, num2TxV1, "5104fe3f420fb67551", true, true},
	{"shift size check: OP_1 <255999999> LSHIFTNUM (result top byte 0x80 -> 32,000,001 bytes)", 0x3d462f, num2TxV1, "5104ff3f420fb67551", false, true},
	{"shift size check: OP_1 <256000000> LSHIFTNUM (pre-check 1+32,000,000 > 32M)", 0x3d462f, num2TxV1, "51040040420fb67551", false, false},
	{"shift size check: <0x80 0x00 = 128> <255999984> LSHIFTNUM (2-byte serialized value: 2+31,999,998=32M)", 0x3d462f, num2TxV1, "02800004f03f420fb67551", true, true},
	{"shift size check: -1 <8> LSHIFTNUM OP_DROP OP_1 (negative shift sanity)", 0x3d462f, num2TxV1, "4f58b67551", true, false},
	{"shift size check: -1 <8> LSHIFTNUM <-256> NUMEQUAL (sign kept)", 0x3d462f, num2TxV1, "4f58b60200819c", true, false},
	{"shift size check: -3 <1> RSHIFTNUM <-1> NUMEQUAL (toward zero)", 0x3d462f, num2TxV1, "018351b701819c", true, false},
	{"shift size check: OP_0 <2147483648> RSHIFTNUM (n > INT_MAX on zero value)", 0x3d462f, num2TxV1, "00050000008000b77551", false, false},
	{"shift size check: OP_1 <2147483647> RSHIFTNUM (n == INT_MAX allowed)", 0x3d462f, num2TxV1, "5104ffffff7fb77551", true, false},
	{"legacy operand fold: OP_LEFT d=9 slot0 fold=0 getint=0", 0x3d462f, num2TxV1, "031d6d1309000000000000000005b482009c", true, false},
	{"legacy operand fold: OP_LEFT d=9 slot0-1 fold=0 getint=0", 0x3d462f, num2TxV1, "032ed91e09000000000000000080b482009c", true, false},
	{"legacy operand fold: OP_RIGHT d=9 slot0-1 fold=0 getint=0", 0x3d462f, num2TxV1, "033f721f09000000000000000080b582009c", true, false},
	{"legacy operand fold: OP_LEFT d=9 deep-slot0 fold=33 getint=33", 0x3d462f, num2TxV1, "2471174494d6493c9d5c3460be31201e69fedaa0eee8b9997f5c7c2999fdafe593253cd65409210000000000000080b48201219c", true, false},
	{"legacy operand fold: OP_SUBSTR(begin) d=9 deep-slot0 fold=33 getint=33", 0x3d462f, num2TxV1, "232955e5cd8e46dc8ed4b7c2764d2a5a4d767706f85d8690024ad6bda3401be9c8cbccc90921000000000000008051b301cc87", true, false},
	{"legacy operand fold: OP_LEFT d=9 d-2 fold=72057594037927936 getint=2147483647", 0x3d462f, num2TxV1, "2835f6cd1f61226ae15338ae1a34004d33ba0d246ac04c81b1baf23e3bf9eef5f79f2b4934af87f552090000000000000001ffb47551", false, false},
	{"legacy operand fold: OP_SUBSTR(begin) d=9 d-2 fold=72057594037927936 getint=2147483647", 0x3d462f, num2TxV1, "2800f5b02b3dc666f45bdeaa2ccaedcd2b5157410e4dee4af2b34f430a073447de636c0e806c957ba6090000000000000001ff51b37551", false, false},
	{"legacy operand fold: OP_LEFT d=10 slot0 fold=107 getint=107", 0x3d462f, num2TxV1, "4c6ed7424d09e15d024c5848f23d1fa6f7361d7f618d1532e70e20e2a6668de7f47e8467e546d53ec8e2a1257bdb256c9b3e4fbb498146ef7030cbf9537252dcceadd764b6a32fbb09adeae109c4a997203975352b878b145c8a42d884cf4cfda72d8e1d5dd92589082d852a7122873e0a6b000000000000000000b482016b9c", true, false},
	{"legacy operand fold: OP_LEFT d=10 slot0-1 fold=0 getint=0", 0x3d462f, num2TxV1, "031a924c0a0000000000000000007fb482009c", true, false},
	{"legacy operand fold: OP_RIGHT d=10 slot0-1 fold=0 getint=0", 0x3d462f, num2TxV1, "037f88df0a0000000000000000007fb582009c", true, false},
	{"legacy operand fold: OP_LEFT d=10 deep-slot0 fold=33 getint=33", 0x3d462f, num2TxV1, "24bfdb0ecc682919d2e64692f8194157f1d4af90988285cf7a9af7c93d5552266afe70e7aa0a00000000000000002180b48201219c", true, false},
	{"legacy operand fold: OP_SUBSTR(begin) d=10 deep-slot0 fold=33 getint=33", 0x3d462f, num2TxV1, "230b4110d9f2fa0025c8efe57f37724f4d37ea2b14004077139b4180df3932249962c6850a0000000000000000218051b301c687", true, false},
	{"legacy operand fold: OP_LEFT d=10 d-2 fold=1 getint=1", 0x3d462f, num2TxV1, "047200059a0a000000000000000001ffb482519c", true, false},
	{"legacy operand fold: OP_SUBSTR(begin) d=10 d-2 fold=1 getint=1", 0x3d462f, num2TxV1, "03f3787e0a000000000000000001ff51b3017887", true, false},
	{"legacy operand fold: OP_LEFT d=16 slot0 fold=0 getint=0", 0x3d462f, num2TxV1, "036734501000000000000000000000000000000080b482009c", true, false},
	{"legacy operand fold: OP_LEFT d=16 slot0-1 fold=256 getint=256", 0x3d462f, num2TxV1, "4d0301f06997233a6eb31c2cd3d0f81bb8d038ca032b54c722b0f019f06123bdc74904ffd1fe2de0032a39471afe62b85087420fcd0347605c55eecd9dae87a11570f272938855dffdb6c6439e52296dd2f8b37498b55a91154187ed7dcf666609661eab35def8047d79ce2f59006b69ab3f6bd97fbdf5e8d13768c92f7268a9471cda11b58a196fe1b6d0fce80058ce27fcb15d77704d1e68645f525d01752a079ff3a78e3d6e027490ee0363ac7815ee72ecfedd28acd839d58dcf9be153b02ab77c367473ea4560e5862c1501e12c02d9a508f8fe8cb0e99b8b581a71dbbaa10de4c93e12dbceb5fedb8570ec40135e0a6daf7f76daadaf97c62435ca482cf255144049c51000010000000000000000000000000080b4820200019c", true, false},
	{"legacy operand fold: OP_RIGHT d=16 slot0-1 fold=256 getint=256", 0x3d462f, num2TxV1, "4d03010b3148a8774cb2e9eff594d62437f336c7149c25e9afb51781e9848dfea5327b0fb5feae71f2f1d69eedbce09e4ee9e1330c78213aa5e2cd11db26de66607c1b675d4c20a0e362e88de1e4b50149888a133d60a3b4099bf5e8cbc5f816a0418ba2252b8b667c3b82ae3a00dc30e4de811120847e05a51127c0cd9ca2336ece3926d2b819a338be64f6a970d3bc7ffe22d4b4fc2e42913ce3224fcec6bc7fae9cb8f1c5d1498ae5ace1a2bf71d8fa12fbdde17a28a85fd73afa83ab79a2b7508f0a0ce81e9e5c296020cdc46b078b9f1e677e3624dbce238b03ec93d22d642573076de161a6f2e61dadb63383255519b611edcd747f56b21fed6074a44dc2c1ac0855011000010000000000000000000000000080b5820200019c", true, false},
	{"legacy operand fold: OP_LEFT d=16 deep-slot0 fold=33 getint=33", 0x3d462f, num2TxV1, "24221ab51d88d48e37f82884ffae090d762d838388cfa000df6433327263d7e7db717d0db71000000000000000002100000000000080b48201219c", true, false},
	{"legacy operand fold: OP_SUBSTR(begin) d=16 deep-slot0 fold=33 getint=33", 0x3d462f, num2TxV1, "231432fa15c1b35c74fad7e625d025f0319958741c314ec3197311311bf1a44fcad7224b100000000000000000210000000000008051b3012287", true, false},
	{"legacy operand fold: OP_LEFT d=16 d-2 fold=281474976710656 getint=2147483647", 0x3d462f, num2TxV1, "284969fc73c7ea9430473d2a93c62ffff06eee4decb2015bad282f92e9476ad5627f2a009467bd2aee10000000000000000000000000000001ffb47551", false, false},
	{"legacy operand fold: OP_SUBSTR(begin) d=16 d-2 fold=281474976710656 getint=2147483647", 0x3d462f, num2TxV1, "28dd5ec26eaf1ff53007e5ba0f05058a5c64764f059a50bb8065aa5fce63bade8140b80095dea6894a10000000000000000000000000000001ff51b37551", false, false},
	{"legacy operand fold: OP_LEFT d=16 slot3-bit31 fold=2147483652 getint=2147483647", 0x3d462f, num2TxV1, "2856bcf7da66f4230512cc42a450b5f5314c9cc5c3db35a06e3208b0df3c197c6a7dd6849f89e543a81004000000000000000000008000000000b47551", false, false},
	{"legacy operand fold: OP_RIGHT d=16 slot3-bit31 fold=2147483652 getint=2147483647", 0x3d462f, num2TxV1, "28389d4f709c28a2a8545039d4225a93370f21a03e23b3fb95c48d2f93b7ac9b1251e02961448d728a1004000000000000000000008000000000b57551", false, false},
	{"legacy operand fold: OP_LEFT d=17 slot0 fold=39 getint=39", 0x3d462f, num2TxV1, "2a78da9c1072822167bcb170c35cbd0d467054ae216ce7325ede7231721a0348ceb5bf1f224fc2fdc69f23110000000000000000270000000000000005b48201279c", true, false},
	{"legacy operand fold: OP_LEFT d=17 slot0-1 fold=1 getint=1", 0x3d462f, num2TxV1, "04bd6d5c1a110000000000000000010000000000000080b482519c", true, false},
	{"legacy operand fold: OP_RIGHT d=17 slot0-1 fold=1 getint=1", 0x3d462f, num2TxV1, "04da15f065110000000000000000010000000000000080b582519c", true, false},
	{"legacy operand fold: OP_LEFT d=17 deep-slot0 fold=33 getint=33", 0x3d462f, num2TxV1, "242d1afe06320bbcff0256fa93c580e65bef63f34e3a9bfdde1b269bc0c10547ec81c65b62110000000000000000210000000000000080b48201219c", true, false},
	{"legacy operand fold: OP_SUBSTR(begin) d=17 deep-slot0 fold=33 getint=33", 0x3d462f, num2TxV1, "23872b96e032a46a606fa5234f15fbd69dbda20fec4f9d6f434c8701b8ce1aeb8537640411000000000000000021000000000000008051b3016487", true, false},
	{"legacy operand fold: OP_LEFT d=17 d-2 fold=72057594037927936 getint=2147483647", 0x3d462f, num2TxV1, "285778e2947bc6516cc4a95c2213afb8b324cd6ddd3f6253e8caf39c6a8cb84651926c6bc2078d56d61100000000000000000000000000000001ffb47551", false, false},
	{"legacy operand fold: OP_SUBSTR(begin) d=17 d-2 fold=72057594037927936 getint=2147483647", 0x3d462f, num2TxV1, "28d9b48428065fda230fbf14e2911a6ed83a0eeb20e93043a1e8ad65602f02c9504560daf43e35d4671100000000000000000000000000000001ff51b37551", false, false},
	{"legacy operand fold: OP_LEFT d=17 slot7-sign fold=-9223372036854775804 getint=-2147483648", 0x3d462f, num2TxV1, "28dc2a3e712edd5802e0f9f4555d738706fefbac95b57ee417cceb6a6992cc799217e44d0f3aac4700110400000000000000000000000000008000b47551", false, false},
	{"legacy operand fold: OP_LEFT d=17 slot3-bit31 fold=2147483652 getint=2147483647", 0x3d462f, num2TxV1, "283b25d9aed1a9e8c6f77765b63942737c838bf5a216808b340d005d1f373048dc5b968fe9851af0f4110400000000000000000000800000000000b47551", false, false},
	{"legacy operand fold: OP_RIGHT d=17 slot3-bit31 fold=2147483652 getint=2147483647", 0x3d462f, num2TxV1, "2864f8d5f306eddd3de5cc4280601e0e0d8fd6c8f2c911659fc00c01160d9e3e5433c6ed68bd283c35110400000000000000000000800000000000b57551", false, false},
	{"legacy operand fold: OP_LEFT d=33 slot0 fold=0 getint=0", 0x3d462f, num2TxV1, "03bb0e33210000000000000000000000000000000000000000000000000000000000000000ffb482009c", true, false},
	{"legacy operand fold: OP_LEFT d=33 slot0-1 fold=257 getint=257", 0x3d462f, num2TxV1, "4d0401f593d60f3efa272cd33549f4cd57519f162ff7581b74da9713e429fb90d852f654da9752263d61afcefe767afc48c36cdaf153b17707cc8cff1d9e46c60a32acf451992a8c869d9d0ecf3ecd10ea708e5364fa75bcd8478e14eefec166fc9b275eb54cb554cad2dc0eaa5cd0def9702f6ca07b01410fd57643ab7b98c7ec3c994f162f7b93aab989358df445131a9a751805acc216209259cf9b6bf1710e6353095a9804efe12d5c6e196e98803b860c3ced0dab157682667d94f25fd52ba2f60e5f87d1e0e22ccadf376d3fd3a9b2dc1143f59ddcad33694ea8a891697df4dba916170649bb8edf53b30272259713a9ec60e8b5191ad74ad1e0c41f68850ff128a8bf1121000000000000000000010000000000000000000000000000010000000000000005b4820201019c", true, false},
	{"legacy operand fold: OP_RIGHT d=33 slot0-1 fold=257 getint=257", 0x3d462f, num2TxV1, "4d040108e7ae36eb7ad2cd7362847c1b74fcf6a9d31e1fe5727ff7667ce8164aa91ec48fc3e3164d7eb8cf7f1224f52920acf9c4642d37ab4ba1210401ab78aa01d45252bf2b4f254fe2f0db00d16774520b8354c86c5701e374254e498522bba48cab74d1561a4b7bf5c8c07bc9d32671451de974637ac27f93d53b5a2cc30a5bed7fc35551c1f442c4a2356b0c24df7a7b1d0799cb238d44f13605b9d3623242cb26e7093c98a7ea0e3bd5535dd43ef96526b6b212630b40772e808bbffda74c76ae297097c8e39e4183d658c5dbeb378996a47e6d0999c472c2779251a132232b12b6b2ebaa43a22f7f89bfdcea4df233a0f3095ed2f502d98292e984efb0b4fe860815ca9021000000000000000000010000000000000000000000000000010000000000000005b5820201019c", true, false},
	{"legacy operand fold: OP_LEFT d=33 deep-slot0 fold=33 getint=33", 0x3d462f, num2TxV1, "240a92cbdf65f507c67680fdd10d32834555ab355060b1d2f088950a601e98ebc7a6824c9721000000000000000000000000000000000000000000000000210000000000000080b48201219c", true, false},
	{"legacy operand fold: OP_SUBSTR(begin) d=33 deep-slot0 fold=33 getint=33", 0x3d462f, num2TxV1, "237a70d73a86f9b8bf0d78791487dd0964118c1d870c8184b92c33aa17f0376deffb0e432100000000000000000000000000000000000000000000000021000000000000008051b3010e87", true, false},
	{"legacy operand fold: OP_LEFT d=33 d-2 fold=72057594037927936 getint=2147483647", 0x3d462f, num2TxV1, "284bb960dae7927b271f1e732ff13f49ab9950caa4ecd0371ec2052c95a08ae8bf3ebfc5a14bda8abb210000000000000000000000000000000000000000000000000000000000000001ffb47551", false, false},
	{"legacy operand fold: OP_SUBSTR(begin) d=33 d-2 fold=72057594037927936 getint=2147483647", 0x3d462f, num2TxV1, "28f05570c554a7e3de3ca3dc32c567ae45d3cf8babe37fdb703cddc290f801fcfb4f2560aa353ac00d210000000000000000000000000000000000000000000000000000000000000001ff51b37551", false, false},
	{"legacy operand fold: OP_LEFT d=33 slot7-sign fold=-9223372036854775804 getint=-2147483648", 0x3d462f, num2TxV1, "2870ec6db2140a89924013b04625d3349320cc42b7383aa00c8b9713516149067ab780859902caf6d221040000000000000000000000000000000000000000000080000000000000000000b47551", false, false},
	{"legacy operand fold: OP_LEFT d=33 slot3-bit31 fold=2147483652 getint=2147483647", 0x3d462f, num2TxV1, "28e57c3c9a4769e6e89d718df8efa2996794b5b6a1c9e200682d85c158ecf43d440bbeae95698dcefc21040000000000000000000000000000000000008000000000000000000000000000b47551", false, false},
	{"legacy operand fold: OP_RIGHT d=33 slot3-bit31 fold=2147483652 getint=2147483647", 0x3d462f, num2TxV1, "28bb97d6b1aba6915df6a93db667e3f7de52ef32b0cdc3eebe910a28e13330d91258f9dede02612d5721040000000000000000000000000000000000008000000000000000000000000000b57551", false, false},
	{"legacy operand fold: OP_LEFT d=65 slot0 fold=32 getint=32", 0x3d462f, num2TxV1, "231b916ab137b3e3b75d9a0b4d827d6e38435c99ac7c4010c3b5d591eedd9b1927cc75fe410000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b48201209c", true, false},
	{"legacy operand fold: OP_LEFT d=65 slot0-1 fold=256 getint=256", 0x3d462f, num2TxV1, "4d03013fd5964ca64d8e536d5a80932cf0d4331f30f7d45194e1e2566211fbe4302b957aacf7b06304c058daf8750ba28c390d5d565bd24b6cc1bf41f96044aa94cbdb8db9278aa7ad4f0b12baad059d15ec0da42b0de16e0999a7a0328cfc609ef8d85280e0859dd10cd07a010d59f8a828da1aa298480005878a7c72b3b2b9519e007823ef849a45928a787185befea84dbc33e630c10ab05bda6ad902c3bc14b26783d9a16635a905850ecdb4cc3b7f3c990c7f214d668960687dba772f54a7665ce20e0b25dcc13c7a9adcdd23c0b7aae04983059626dc72ef267c056fa9b92b370a2234b55fa2297891d0ac08acc8ab6e1267f2973e00d3752ecc33e7fbd854f2922b094100000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffb4820200019c", true, false},
	{"legacy operand fold: OP_RIGHT d=65 slot0-1 fold=256 getint=256", 0x3d462f, num2TxV1, "4d0301cb37cd35a3f7ae4f27d138df5125fd41878ab51cb6e2ea13d6496b56511b871cbd21877a16f9fa4b5f96e6dc178776a338dde18d43809f357aa2260c52018ff2dda510f58ce1c060d9ecb7dbe5349710a305264cccb8ec06beb615eacca58bb1bf76e1bb62f3b4a63164603ec7665f3bfad4962053eb71abce470bf949312c52759a76d8a91ae29dda9945f539d1af5ecfbb13ac8b6497c35d50c31522d66dce755371f769f7fa60cb4f0961fc2ce4e7f2428ad4ba9812fcbe36a6a3fcc265a02da953ef4522ec61bcb4a1f49c099145aada1837d2c88f5e39a77619459228a3f3b0085906beb84c4ff0ae77d24751b11005a85887662c4e1c51d56dabc9a5dd04bdab4100000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffb5820200019c", true, false},
	{"legacy operand fold: OP_LEFT d=65 deep-slot0 fold=33 getint=33", 0x3d462f, num2TxV1, "242ae89f6212b53de4221893af5f6301d3bf39a19a096a46ea7fdbf4dc63b85827b6024797410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000210000000000000080b48201219c", true, false},
	{"legacy operand fold: OP_SUBSTR(begin) d=65 deep-slot0 fold=33 getint=33", 0x3d462f, num2TxV1, "23088edd4f78b54d4aa0d13c5e04414b3bc50c6cb19cd2b9bb82bb9023c74a0bed13301241000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000021000000000000008051b3013087", true, false},
	{"legacy operand fold: OP_LEFT d=65 d-2 fold=72057594037927936 getint=2147483647", 0x3d462f, num2TxV1, "280d758f909d8664ed07ae9f38b118c10a70d3e3fa4d140c24ece6a32794151be1fa53eea595c190444100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ffb47551", false, false},
	{"legacy operand fold: OP_SUBSTR(begin) d=65 d-2 fold=72057594037927936 getint=2147483647", 0x3d462f, num2TxV1, "288a411018d1d15cd345b686bc19be14ccef87ea0eadb2ea3b523f1fd2271bf8452231d69fdb0c02564100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ff51b37551", false, false},
	{"legacy operand fold: OP_LEFT d=65 slot7-sign fold=-9223372036854775804 getint=-2147483648", 0x3d462f, num2TxV1, "2835d422709f3d9a86b1b2da690442768f05078aae0c875c350f44ebb99e948bbe1b3f7de9ea4aadb0410400000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000b47551", false, false},
	{"legacy operand fold: OP_LEFT d=65 slot3-bit31 fold=2147483652 getint=2147483647", 0x3d462f, num2TxV1, "286a5d8db8dee37b3e438586be23fcb2ecc6209786f8b2b8775fd124c4d185f606abd5315ba3fa2b2c410400000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000b47551", false, false},
	{"legacy operand fold: OP_RIGHT d=65 slot3-bit31 fold=2147483652 getint=2147483647", 0x3d462f, num2TxV1, "285c52d4846677632363ed995682c3f17be8795607d4e2135013cc26201a40bfb69e7af58b3c5f2e97410400000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000b57551", false, false},
	{"legacy operand fold: OP_LEFT d=129 slot0 fold=125 getint=125", 0x3d462f, num2TxV1, "4c804c1697e7b569fa857c9cf38236da82ef85465ec2f5d12f4b12ff753ec9ff1b0739ce884365ba78ef4a25744f7857c97d09e78d5bf1953af7398fb49eb2a846dc894cb28a3d077549dff47d477a6f1ff99673b93ba0ed30cdbf25bc9e7785d0959bce167c0d5503bdc54700239ba20bc7c9186f54f471d25e069e3ad8a2d436414c813c000000000000004c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011000000000000007500000000000000690000000000000000000000000000000000000000000000000000000000000080b482017d9c", true, false},
	{"legacy operand fold: OP_LEFT d=129 slot0-1 fold=257 getint=257", 0x3d462f, num2TxV1, "4d04013fa1fe5626f9b5d2432f1ca2db7d6465b7ac9850d3a0c9e915a808475b8e42850384159531d6d269204933c6bac1bb086c872006adc9cdb3d8a2bc1ca4ef44d5a3b0e368530bda4b1e4f7e5d010344d1611f8551f58e36fde76392d9fd3993c94a972d3fa6671a7288e4760764e30f5646fe94a3eae40ff5356eec47a76ec56766dd891cf46b5cfa815e68992ea0b8a076542feb7a132c2085098d6f12778b8224cfaed15dce07dda4e986795e5f7242105a70151285682ad78f3fe2f8fef73b92de2a47037ea68c13586729281d3f408b0bce0a9857ad9b9cbbf6341eded66d3c5b633b876a35c1936f1ef6c2bc3f05c0285e80e371a268d4e24eb82954e18d3bfbf8b04c810000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000100000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000ffb4820201019c", true, false},
	{"legacy operand fold: OP_RIGHT d=129 slot0-1 fold=257 getint=257", 0x3d462f, num2TxV1, "4d0401d40ea5527ce963d7332fc43feb504e006d3a57a476fe04716464cc5b1c93e402be074884754bce1966c715ad7280485738757bc1bea67ee930f01c14c70413efe981417293f8943bfdc5a9488eb925839d43afb54c3a34de3093f2e808335b28ba8519be4419e86f280dd1f9a6728d58019fbde8c174d63fe0991a4df15070ab80cba15dfdc02d735f4dd015c9880e43976731d0b4c2f0f475ecf144f2db599bc0cf342f52ae24b2b2ec79302cd28c7feee140dd109cf4c5a52f33a6eb38f5c3d762b957fe3ab1e98290c57eb911bd937887c03c748c5774de6e73b2e07e79b6fafff7690367342d6c19f98bb15f0ef6d92136b5fcfbd1c40fd3ebea470b118a136353374c810000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000100000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000ffb5820201019c", true, false},
	{"legacy operand fold: OP_LEFT d=129 deep-slot0 fold=33 getint=33", 0x3d462f, num2TxV1, "24ca58490ad674b5949c064afb5c745f0de30e4a2d1a9494e981a5aa040f04e0f8bbc1fa3c4c81000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000210000000000000080b48201219c", true, false},
	{"legacy operand fold: OP_SUBSTR(begin) d=129 deep-slot0 fold=33 getint=33", 0x3d462f, num2TxV1, "23173a56bfb45408f3e139c3eb83d20a27819fe695f0050ce8553f43ff787d96ce63aac64c8100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000021000000000000008051b301aa87", true, false},
	{"legacy operand fold: OP_LEFT d=129 d-2 fold=72057594037927936 getint=2147483647", 0x3d462f, num2TxV1, "2894bc70dc5e0fb2ba7edde3177f99bda7be1bac3116dd9dbae0d4159e8b98336f6637a9cbe58e75374c810000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ffb47551", false, false},
	{"legacy operand fold: OP_SUBSTR(begin) d=129 d-2 fold=72057594037927936 getint=2147483647", 0x3d462f, num2TxV1, "28fbcd89e61d75c5d111db01d65a4fa5c4664658feacb6cdc6fa1e75a9362d860c82221a8c012e6ce54c810000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ff51b37551", false, false},
	{"legacy operand fold: OP_LEFT d=129 slot7-sign fold=-9223372036854775804 getint=-2147483648", 0x3d462f, num2TxV1, "284e8c3175c0782e9387f29a7df1b60dab2046820e9922f8e3ed460be067c2596ec189581d2dff9d154c81040000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b47551", false, false},
	{"legacy operand fold: OP_LEFT d=129 slot3-bit31 fold=2147483652 getint=2147483647", 0x3d462f, num2TxV1, "28f27a516e1afcbcc45cec39ec000e0b15c22d3cf5ca124c9248366a4f7e8e6e50a33e6316b974a6c44c81040000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b47551", false, false},
	{"legacy operand fold: OP_RIGHT d=129 slot3-bit31 fold=2147483652 getint=2147483647", 0x3d462f, num2TxV1, "28626dbc2be89b9621e70103fe1860954a226ce3211c1b576d53a37b850a9e193681f17172049f99294c81040000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b57551", false, false},
	{"legacy operand fold: OP_LEFT d=1000 slot0 fold=127 getint=127", 0x3d462f, num2TxV1, "4c8281897d508317699b5d552a8ed77b0b7f507ddaab428da3bab35cd3853c13034b4dbabe017a91e78a922ac62be2778a5018639f27328cf74664fbe48c997bcb3fadafa9296e66deb6af9d98f4a36ac422ad4da8d361c73de7c7f8874b3dceb2f7fe332669499a0d5c9578303868eaa4d4a0fbefb1ae9f813e42757e834f113b27fe574de803340000000000000000000000000000000000000000000000000000000000000000000000000000000500000000000000310000000000000000000000000000000000000000000000170000000000000000000000000000000000000000000000000000000000000000000000000000005e0000000000000000000000000000000000000000000000170000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000410000000000000070000000000000003a000000000000006800000000000000180000000000000035000000000000000000000000000000440000000000000000000000000000000000000000000000440000000000000000000000000000000000000000000000000000000000000057000000000000000000000000000000150000000000000000000000000000003c00000000000000210000000000000063000000000000000000000000000000000000000000000000000000000000004a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003e0000000000000000000000000000005a0000000000000000000000000000005700000000000000290000000000000000000000000000007c000000000000000000000000000000000000000000000000000000000000002b00000000000000130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000140000000000000000000000000000001c0000000000000000000000000000000000000000000000150000000000000000000000000000000000000000000000000000000000000015000000000000000000000000000000000000000000000056000000000000002b0000000000000000000000000000000000000000000000000000000000000000000000000000005d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005b00000000000000000000000000000071000000000000ffb482017f9c", true, false},
	{"legacy operand fold: OP_SUBSTR(begin) d=1000 deep-slot0 fold=33 getint=33", 0x3d462f, num2TxV1, "2394d1ba8aac75c39a6f3f6646126935c24c05758a721cb7f72b5bf1095e8090967e418e4de8030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000210000000000008051b3014187", true, false},
	{"shift boundary: one-r0 OP_LSHIFTNUM val=1 n=255999992", 0x3d462f, num2TxV1, "5104f83f420fb604f83f420fb7519c", true, true},
	{"shift boundary: neg1-r0 OP_LSHIFTNUM val=-1 n=255999992", 0x3d462f, num2TxV1, "4f04f83f420fb604f83f420fb74f9c", true, true},
	{"shift boundary: one-r1 OP_LSHIFTNUM val=1 n=255999993", 0x3d462f, num2TxV1, "5104f93f420fb604f93f420fb7519c", true, true},
	{"shift boundary: neg1-r1 OP_LSHIFTNUM val=-1 n=255999993", 0x3d462f, num2TxV1, "4f04f93f420fb604f93f420fb74f9c", true, true},
	{"shift boundary: one-r2 OP_LSHIFTNUM val=1 n=255999994", 0x3d462f, num2TxV1, "5104fa3f420fb604fa3f420fb7519c", true, true},
	{"shift boundary: neg1-r2 OP_LSHIFTNUM val=-1 n=255999994", 0x3d462f, num2TxV1, "4f04fa3f420fb604fa3f420fb74f9c", true, true},
	{"shift boundary: one-r3 OP_LSHIFTNUM val=1 n=255999995", 0x3d462f, num2TxV1, "5104fb3f420fb604fb3f420fb7519c", true, true},
	{"shift boundary: neg1-r3 OP_LSHIFTNUM val=-1 n=255999995", 0x3d462f, num2TxV1, "4f04fb3f420fb604fb3f420fb74f9c", true, true},
	{"shift boundary: one-r4 OP_LSHIFTNUM val=1 n=255999996", 0x3d462f, num2TxV1, "5104fc3f420fb604fc3f420fb7519c", true, true},
	{"shift boundary: neg1-r4 OP_LSHIFTNUM val=-1 n=255999996", 0x3d462f, num2TxV1, "4f04fc3f420fb604fc3f420fb74f9c", true, true},
	{"shift boundary: one-r5 OP_LSHIFTNUM val=1 n=255999997", 0x3d462f, num2TxV1, "5104fd3f420fb604fd3f420fb7519c", true, true},
	{"shift boundary: neg1-r5 OP_LSHIFTNUM val=-1 n=255999997", 0x3d462f, num2TxV1, "4f04fd3f420fb604fd3f420fb74f9c", true, true},
	{"shift boundary: one-r6 OP_LSHIFTNUM val=1 n=255999998", 0x3d462f, num2TxV1, "5104fe3f420fb604fe3f420fb7519c", true, true},
	{"shift boundary: neg1-r6 OP_LSHIFTNUM val=-1 n=255999998", 0x3d462f, num2TxV1, "4f04fe3f420fb604fe3f420fb74f9c", true, true},
	{"shift boundary: one-r7 OP_LSHIFTNUM val=1 n=255999999", 0x3d462f, num2TxV1, "5104ff3f420fb67551", false, true},
	{"shift boundary: neg1-r7 OP_LSHIFTNUM val=-1 n=255999999", 0x3d462f, num2TxV1, "4f04ff3f420fb67551", false, true},
	{"shift boundary: v0x40-r0 OP_LSHIFTNUM val=64 n=255999992", 0x3d462f, num2TxV1, "014004f83f420fb604f83f420fb701409c", true, true},
	{"shift boundary: v0x40-r1 OP_LSHIFTNUM val=64 n=255999993", 0x3d462f, num2TxV1, "014004f93f420fb67551", false, true},
	{"shift boundary: v0x40-r7 OP_LSHIFTNUM val=64 n=255999999", 0x3d462f, num2TxV1, "014004ff3f420fb67551", false, true},
	{"shift boundary: v0x40-r8 OP_LSHIFTNUM val=64 n=256000000", 0x3d462f, num2TxV1, "0140040040420fb67551", false, false},
	{"shift boundary: v0x7f-r0 OP_LSHIFTNUM val=127 n=255999992", 0x3d462f, num2TxV1, "017f04f83f420fb604f83f420fb7017f9c", true, true},
	{"shift boundary: v0x7f-r1 OP_LSHIFTNUM val=127 n=255999993", 0x3d462f, num2TxV1, "017f04f93f420fb67551", false, true},
	{"shift boundary: v0x7f-r7 OP_LSHIFTNUM val=127 n=255999999", 0x3d462f, num2TxV1, "017f04ff3f420fb67551", false, true},
	{"shift boundary: v0x7f-r8 OP_LSHIFTNUM val=127 n=256000000", 0x3d462f, num2TxV1, "017f040040420fb67551", false, false},
	{"shift boundary: v0x80-r0 OP_LSHIFTNUM val=128 n=255999984", 0x3d462f, num2TxV1, "02800004f03f420fb604f03f420fb70280009c", true, true},
	{"shift boundary: v0x80-r1 OP_LSHIFTNUM val=128 n=255999985", 0x3d462f, num2TxV1, "02800004f13f420fb604f13f420fb70280009c", true, true},
	{"shift boundary: v0x80-r7 OP_LSHIFTNUM val=128 n=255999991", 0x3d462f, num2TxV1, "02800004f73f420fb604f73f420fb70280009c", true, true},
	{"shift boundary: v0x80-r8 OP_LSHIFTNUM val=128 n=255999992", 0x3d462f, num2TxV1, "02800004f83f420fb67551", false, false},
	{"shift boundary: v0xff-r0 OP_LSHIFTNUM val=255 n=255999984", 0x3d462f, num2TxV1, "02ff0004f03f420fb604f03f420fb702ff009c", true, true},
	{"shift boundary: v0xff-r1 OP_LSHIFTNUM val=255 n=255999985", 0x3d462f, num2TxV1, "02ff0004f13f420fb604f13f420fb702ff009c", true, true},
	{"shift boundary: v0xff-r7 OP_LSHIFTNUM val=255 n=255999991", 0x3d462f, num2TxV1, "02ff0004f73f420fb604f73f420fb702ff009c", true, true},
	{"shift boundary: v0xff-r8 OP_LSHIFTNUM val=255 n=255999992", 0x3d462f, num2TxV1, "02ff0004f83f420fb67551", false, false},
	{"shift boundary: v0x100-r0 OP_LSHIFTNUM val=256 n=255999984", 0x3d462f, num2TxV1, "02000104f03f420fb604f03f420fb70200019c", true, true},
	{"shift boundary: v0x100-r1 OP_LSHIFTNUM val=256 n=255999985", 0x3d462f, num2TxV1, "02000104f13f420fb604f13f420fb70200019c", true, true},
	{"shift boundary: v0x100-r7 OP_LSHIFTNUM val=256 n=255999991", 0x3d462f, num2TxV1, "02000104f73f420fb67551", false, true},
	{"shift boundary: v0x100-r8 OP_LSHIFTNUM val=256 n=255999992", 0x3d462f, num2TxV1, "02000104f83f420fb67551", false, false},
	{"shift boundary: v0x7fff-r0 OP_LSHIFTNUM val=32767 n=255999984", 0x3d462f, num2TxV1, "02ff7f04f03f420fb604f03f420fb702ff7f9c", true, true},
	{"shift boundary: v0x7fff-r1 OP_LSHIFTNUM val=32767 n=255999985", 0x3d462f, num2TxV1, "02ff7f04f13f420fb67551", false, true},
	{"shift boundary: v0x7fff-r7 OP_LSHIFTNUM val=32767 n=255999991", 0x3d462f, num2TxV1, "02ff7f04f73f420fb67551", false, true},
	{"shift boundary: v0x7fff-r8 OP_LSHIFTNUM val=32767 n=255999992", 0x3d462f, num2TxV1, "02ff7f04f83f420fb67551", false, false},
	{"shift boundary: v0x8000-r0 OP_LSHIFTNUM val=32768 n=255999976", 0x3d462f, num2TxV1, "0300800004e83f420fb604e83f420fb7030080009c", true, true},
	{"shift boundary: v0x8000-r1 OP_LSHIFTNUM val=32768 n=255999977", 0x3d462f, num2TxV1, "0300800004e93f420fb604e93f420fb7030080009c", true, true},
	{"shift boundary: v0x8000-r7 OP_LSHIFTNUM val=32768 n=255999983", 0x3d462f, num2TxV1, "0300800004ef3f420fb604ef3f420fb7030080009c", true, true},
	{"shift boundary: v0x8000-r8 OP_LSHIFTNUM val=32768 n=255999984", 0x3d462f, num2TxV1, "0300800004f03f420fb67551", false, false},
	{"shift boundary: v-0x40-r0 OP_LSHIFTNUM val=-64 n=255999992", 0x3d462f, num2TxV1, "01c004f83f420fb604f83f420fb701c09c", true, true},
	{"shift boundary: v-0x40-r1 OP_LSHIFTNUM val=-64 n=255999993", 0x3d462f, num2TxV1, "01c004f93f420fb67551", false, true},
	{"shift boundary: v-0x40-r7 OP_LSHIFTNUM val=-64 n=255999999", 0x3d462f, num2TxV1, "01c004ff3f420fb67551", false, true},
	{"shift boundary: v-0x40-r8 OP_LSHIFTNUM val=-64 n=256000000", 0x3d462f, num2TxV1, "01c0040040420fb67551", false, false},
	{"shift boundary: v-0x80-r0 OP_LSHIFTNUM val=-128 n=255999984", 0x3d462f, num2TxV1, "02808004f03f420fb604f03f420fb70280809c", true, true},
	{"shift boundary: v-0x80-r1 OP_LSHIFTNUM val=-128 n=255999985", 0x3d462f, num2TxV1, "02808004f13f420fb604f13f420fb70280809c", true, true},
	{"shift boundary: v-0x80-r7 OP_LSHIFTNUM val=-128 n=255999991", 0x3d462f, num2TxV1, "02808004f73f420fb604f73f420fb70280809c", true, true},
	{"shift boundary: v-0x80-r8 OP_LSHIFTNUM val=-128 n=255999992", 0x3d462f, num2TxV1, "02808004f83f420fb67551", false, false},
	{"shift boundary: zero OP_LSHIFTNUM val=0 n=255999999", 0x3d462f, num2TxV1, "0004ff3f420fb604ff3f420fb7009c", true, false},
	{"shift boundary: zeroR OP_RSHIFTNUM val=0 n=255999999", 0x3d462f, num2TxV1, "0004ff3f420fb7009c", true, false},
	{"shift boundary: zero OP_LSHIFTNUM val=0 n=256000000", 0x3d462f, num2TxV1, "00040040420fb6040040420fb7009c", true, false},
	{"shift boundary: zeroR OP_RSHIFTNUM val=0 n=256000000", 0x3d462f, num2TxV1, "00040040420fb7009c", true, false},
	{"shift boundary: zero OP_LSHIFTNUM val=0 n=256000007", 0x3d462f, num2TxV1, "00040740420fb6040740420fb7009c", true, false},
	{"shift boundary: zeroR OP_RSHIFTNUM val=0 n=256000007", 0x3d462f, num2TxV1, "00040740420fb7009c", true, false},
	{"shift boundary: zero OP_LSHIFTNUM val=0 n=256000008", 0x3d462f, num2TxV1, "00040840420fb67551", false, false},
	{"shift boundary: zeroR OP_RSHIFTNUM val=0 n=256000008", 0x3d462f, num2TxV1, "00040840420fb7009c", true, false},
	{"shift boundary: zero OP_LSHIFTNUM val=0 n=2147483647", 0x3d462f, num2TxV1, "0004ffffff7fb67551", false, false},
	{"shift boundary: zeroR OP_RSHIFTNUM val=0 n=2147483647", 0x3d462f, num2TxV1, "0004ffffff7fb7009c", true, false},
	{"shift boundary: zero OP_LSHIFTNUM val=0 n=2147483648", 0x3d462f, num2TxV1, "00050000008000b67551", false, false},
	{"shift boundary: zeroR OP_RSHIFTNUM val=0 n=2147483648", 0x3d462f, num2TxV1, "00050000008000b77551", false, false},
	{"shift boundary: zero OP_LSHIFTNUM val=0 n=1099511627776", 0x3d462f, num2TxV1, "0006000000000001b67551", false, false},
	{"shift boundary: zeroR OP_RSHIFTNUM val=0 n=1099511627776", 0x3d462f, num2TxV1, "0006000000000001b77551", false, false},
	{"shift boundary: zero-9byte-n OP_LSHIFTNUM val=0 n=9223372036854775808", 0x3d462f, num2TxV1, "0009000000000000008000b67551", false, false},
	{"shift boundary: one-1000byte-n OP_LSHIFTNUM val=1 n=169693557806454547460920357372495729552675572363395752487473912600842164084431648891693685185664896814456244494299812107409399875472264297698570005314170111295189581385309758385155280067668666557390136908980593715426666607399029173501815996679845701715343133331016016510936770947855633420674170145046020143289588502739666829560652003019181562403052164057314375109589034088890196635238327173548568995711696820878755967774472150519707965517035262027134181291199261893348271341398660612628643085752698788650336798844029779207647952247188638778878595991962373417494659282460903524653627033853045487632335245630107786441881540807160483599877098867981923048660911967141642437108114639331475547247140889094124915569045049025810729138009631182684435328886924885602523931689477436908515761167840317035003289064937587847701581996113161705903838093504877338380376550924784260380733755945431409951714223157464828363285300425820526500433017947068370711643278448558224316561851353950783151954779321394422161149470877502585132286158578460389526231842301530428098905305001070568482960566655924419126747522664008195220465709794597188040053441769770801639439542676331488358503026375979863506207482411387087181626975860785230549593170727023147949067034097253701314828865284827683374351583817549837315472457985392764179353380627738502097149175346762966858267840505705500831466592328522467364402960917137276659587855420487510468712326568132882163294262541708316606476639047039795010759731039121372304792149961933525884460888899605519494396455988289881132578939763770551085655048297899093851522124039442280049699282487745340760694697497483243521535875170078546477561985563541761887646258615081646952220572512562868226951254981663297420258087848405433473222548592895464878586247634884903389583064995420190037972744123905906224629164546798538148866731345906194467162672123867453170972298688231947308884898366807937923167617829622607922243067161400100854814379542447030415150956224957783782656237437261610745716176297880472704949447077436654670199932369079404209671540699319772582126592845852819453164304528460602171918999623121202961176991809285487571092053601013102361757875903368982854854302388290453432402449248063167442932224188839394505862697947170921709089895541645637771687542888175866454060882891627323036050320820280516591150968776488695228597062277230980922820942433650603663096199678963169831723980280497930417653940224", 0x3d462f, num2TxV1, "514de703000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040b67551", false, false},
	{"shift boundary: oneR-1000byte-n OP_RSHIFTNUM val=1 n=169693557806454547460920357372495729552675572363395752487473912600842164084431648891693685185664896814456244494299812107409399875472264297698570005314170111295189581385309758385155280067668666557390136908980593715426666607399029173501815996679845701715343133331016016510936770947855633420674170145046020143289588502739666829560652003019181562403052164057314375109589034088890196635238327173548568995711696820878755967774472150519707965517035262027134181291199261893348271341398660612628643085752698788650336798844029779207647952247188638778878595991962373417494659282460903524653627033853045487632335245630107786441881540807160483599877098867981923048660911967141642437108114639331475547247140889094124915569045049025810729138009631182684435328886924885602523931689477436908515761167840317035003289064937587847701581996113161705903838093504877338380376550924784260380733755945431409951714223157464828363285300425820526500433017947068370711643278448558224316561851353950783151954779321394422161149470877502585132286158578460389526231842301530428098905305001070568482960566655924419126747522664008195220465709794597188040053441769770801639439542676331488358503026375979863506207482411387087181626975860785230549593170727023147949067034097253701314828865284827683374351583817549837315472457985392764179353380627738502097149175346762966858267840505705500831466592328522467364402960917137276659587855420487510468712326568132882163294262541708316606476639047039795010759731039121372304792149961933525884460888899605519494396455988289881132578939763770551085655048297899093851522124039442280049699282487745340760694697497483243521535875170078546477561985563541761887646258615081646952220572512562868226951254981663297420258087848405433473222548592895464878586247634884903389583064995420190037972744123905906224629164546798538148866731345906194467162672123867453170972298688231947308884898366807937923167617829622607922243067161400100854814379542447030415150956224957783782656237437261610745716176297880472704949447077436654670199932369079404209671540699319772582126592845852819453164304528460602171918999623121202961176991809285487571092053601013102361757875903368982854854302388290453432402449248063167442932224188839394505862697947170921709089895541645637771687542888175866454060882891627323036050320820280516591150968776488695228597062277230980922820942433650603663096199678963169831723980280497930417653940224", 0x3d462f, num2TxV1, "514de703000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040b77551", false, false},
	{"shift boundary: zero-n0 OP_LSHIFTNUM val=0 n=0", 0x3d462f, num2TxV1, "0000b6009c", true, false},
	{"shift boundary: one-n0 OP_LSHIFTNUM val=1 n=0", 0x3d462f, num2TxV1, "5100b6519c", true, false},
	{"shift boundary: R-neg OP_RSHIFTNUM val=-5 n=1", 0x3d462f, num2TxV1, "018551b701829c", true, false},
	{"shift boundary: R-neg-big OP_RSHIFTNUM val=big n=99", 0x3d462f, num2TxV1, "0d010000000000000000000000900163b701829c", true, false},
	{"shift boundary: R-INT_MAX OP_RSHIFTNUM val=12345 n=2147483647", 0x3d462f, num2TxV1, "02393004ffffff7fb7009c", true, false},
	{"shift boundary: L-small OP_LSHIFTNUM val=-3 n=5", 0x3d462f, num2TxV1, "018355b601e09c", true, false},
	{"shift boundary: L-100bits OP_LSHIFTNUM val=4660 n=100", 0x3d462f, num2TxV1, "0234120164b60164b70234129c", true, false},
	{"seed-42 sweep case 3094: v1 w3d462f", 0x3d462f, "0100000001bbbabdbcb7b6b9b8c3c2c5c4bfbec1c0cbcacdccc7c6c9c8d3d2d5d4cfced1d00000000015018007b024191f210f7d0180018006f92707076ce5ffffffff010100000000000000015100000000", "0a32cdbdf8e31089ebebc9949801667707974aee146a59bf032bd20087a4906e0180a45f", true, false},
	{"seed-42 sweep case 3094: v1 w3d47ff", 0x3d47ff, "0100000001bbbabdbcb7b6b9b8c3c2c5c4bfbec1c0cbcacdccc7c6c9c8d3d2d5d4cfced1d00000000015018007b024191f210f7d0180018006f92707076ce5ffffffff010100000000000000015100000000", "0a32cdbdf8e31089ebebc9949801667707974aee146a59bf032bd20087a4906e0180a45f", false, false},
	{"seed-42 sweep case 3094: v1 w1d462f", 0x1d462f, "0100000001bbbabdbcb7b6b9b8c3c2c5c4bfbec1c0cbcacdccc7c6c9c8d3d2d5d4cfced1d00000000015018007b024191f210f7d0180018006f92707076ce5ffffffff010100000000000000015100000000", "0a32cdbdf8e31089ebebc9949801667707974aee146a59bf032bd20087a4906e0180a45f", true, false},
	{"seed-42 sweep case 3094: v1 w15462f", 0x15462f, "0100000001bbbabdbcb7b6b9b8c3c2c5c4bfbec1c0cbcacdccc7c6c9c8d3d2d5d4cfced1d00000000015018007b024191f210f7d0180018006f92707076ce5ffffffff010100000000000000015100000000", "0a32cdbdf8e31089ebebc9949801667707974aee146a59bf032bd20087a4906e0180a45f", false, false},
	{"seed-42 sweep case 3094: v2 w3d462f", 0x3d462f, "0200000001bbbabdbcb7b6b9b8c3c2c5c4bfbec1c0cbcacdccc7c6c9c8d3d2d5d4cfced1d00000000015018007b024191f210f7d0180018006f92707076ce5ffffffff010100000000000000015100000000", "0a32cdbdf8e31089ebebc9949801667707974aee146a59bf032bd20087a4906e0180a45f", true, false},
	{"seed-42 sweep case 3094: v2 w3d47ff", 0x3d47ff, "0200000001bbbabdbcb7b6b9b8c3c2c5c4bfbec1c0cbcacdccc7c6c9c8d3d2d5d4cfced1d00000000015018007b024191f210f7d0180018006f92707076ce5ffffffff010100000000000000015100000000", "0a32cdbdf8e31089ebebc9949801667707974aee146a59bf032bd20087a4906e0180a45f", true, false},
	{"seed-42 sweep case 3094: v2 w1d462f", 0x1d462f, "0200000001bbbabdbcb7b6b9b8c3c2c5c4bfbec1c0cbcacdccc7c6c9c8d3d2d5d4cfced1d00000000015018007b024191f210f7d0180018006f92707076ce5ffffffff010100000000000000015100000000", "0a32cdbdf8e31089ebebc9949801667707974aee146a59bf032bd20087a4906e0180a45f", true, false},
	{"seed-42 sweep case 3094: v2 w15462f", 0x15462f, "0200000001bbbabdbcb7b6b9b8c3c2c5c4bfbec1c0cbcacdccc7c6c9c8d3d2d5d4cfced1d00000000015018007b024191f210f7d0180018006f92707076ce5ffffffff010100000000000000015100000000", "0a32cdbdf8e31089ebebc9949801667707974aee146a59bf032bd20087a4906e0180a45f", false, false},
	{"BN_mul limit: mul words 1048575 x 1048575", 0x3d462f, num2TxV2, "0003f7ff7f8001017e0003f7ff7f8001017e957551", true, true},
	{"BN_mul limit: mul words 1048576 x 1048576", 0x3d462f, num2TxV2, "0003f8ff7f8001017e0003f8ff7f8001017e957551", true, true},
	{"BN_mul limit: mul words 1048576 x 1048576", 0x3d462f, num2TxV2, "0003ffff7f8001017e0003ffff7f8001017e957551", true, true},
	{"BN_mul limit: mul words 1048577 x 1048577", 0x3d462f, num2TxV2, "0004000080008001017e0004000080008001017e957551", false, false},
	{"BN_mul limit: mul words 1048577 x 1048576", 0x3d462f, num2TxV2, "0004000080008001017e0003f8ff7f8001017e957551", false, false},
	{"BN_mul limit: mul words 1048576 x 1048577", 0x3d462f, num2TxV2, "0003f8ff7f8001017e0004000080008001017e957551", false, false},
	{"BN_mul limit: MULBN words 1048577 x 1048577", 0x3d462f, num2TxV1, "0004000080008001017e0004000080008001017e957551", false, true},
	{"BN_mul limit: MULBN words 1048577 x 1048577 (neg a)", 0x3d462f, num2TxV1, "0004000080008001817e0004000080008001017e957551", false, true},
	{"BN_mul limit: MULBN words 1048577 x 1048576", 0x3d462f, num2TxV1, "0004000080008001017e0003f8ff7f8001017e957551", false, false},
	{"BN_mul limit: MULBN words 1048576 x 1048577", 0x3d462f, num2TxV1, "0003f8ff7f8001017e0004000080008001017e957551", false, false},
	{"BN_mul limit: MULBN words 1048576 x 1048576", 0x3d462f, num2TxV1, "0003f8ff7f8001017e0003f8ff7f8001017e957551", true, true},
	{"BN_mul limit: MULBN words 1048576 x 1048576 (neg a)", 0x3d462f, num2TxV1, "0003f8ff7f8001817e0003f8ff7f8001017e957551", true, true},
	{"BN_mul limit: MULBN words 1048576 x 1048575", 0x3d462f, num2TxV1, "0003f8ff7f8001017e0003f0ff7f8001017e957551", true, true},
	{"BN_mul limit: MULBN words 1048575 x 1048576", 0x3d462f, num2TxV1, "0003f0ff7f8001017e0003f8ff7f8001017e957551", true, true},
	{"BN_mul limit: MULBN words 1048575 x 1048575", 0x3d462f, num2TxV1, "0003f0ff7f8001017e0003f0ff7f8001017e957551", true, true},
	{"BN_mul limit: MULBN words 1048578 x 1048577", 0x3d462f, num2TxV1, "0004080080008001017e0004000080008001017e957551", false, false},
	{"BN_mul limit: MULBN words 2000000 x 1999999", 0x3d462f, num2TxV1, "0004f823f4008001017e0004f023f4008001017e957551", false, true},
	{"BN_mul limit: MULBN words 2000000 x 1999999 (neg a)", 0x3d462f, num2TxV1, "0004f823f4008001817e0004f023f4008001017e957551", false, true},
	{"BN_mul limit: MULBN words 1999999 x 2000000", 0x3d462f, num2TxV1, "0004f023f4008001017e0004f823f4008001017e957551", false, true},
	{"BN_mul limit: MULBN words 2000000 x 2000000", 0x3d462f, num2TxV1, "0004f823f4008001017e0004f823f4008001017e957551", false, true},
	{"BN_mul limit: MULBN words 1500000 x 1500001", 0x3d462f, num2TxV1, "0004f81ab7008001017e0004001bb7008001017e957551", false, true},
	{"BN_mul limit: MULBN words 1048577 x 16", 0x3d462f, num2TxV1, "0004000080008001017e0001788001017e957551", true, true},
	{"BN_mul limit: MULBN words 1048577 x 16 (neg a)", 0x3d462f, num2TxV1, "0004000080008001817e0001788001017e957551", true, true},
	{"BN_mul limit: MULBN words 16 x 1048577", 0x3d462f, num2TxV1, "0001788001017e0004000080008001017e957551", true, true},
	{"BN_mul limit: MULBN words 2000000 x 16", 0x3d462f, num2TxV1, "0004f823f4008001017e0001788001017e957551", true, true},
	{"BN_mul limit: MULBN words 3999000 x 17", 0x3d462f, num2TxV1, "0004b828e8018001017e000280008001017e957551", true, true},
	{"BN_mul limit: MULBN words 1048577 x 1000", 0x3d462f, num2TxV1, "0004000080008001017e0002381f8001017e957551", true, true},
	{"BN_mul limit: MULBN words 1048577 x 15", 0x3d462f, num2TxV1, "0004000080008001017e0001708001017e957551", true, true},
	{"BN_mul limit: MULBN words 16 x 16", 0x3d462f, num2TxV1, "0001788001017e0001788001017e957551", true, false},
	{"BN_mul limit: MULBN words 16 x 17", 0x3d462f, num2TxV1, "0001788001017e000280008001017e957551", true, false},
	{"BN_mul limit: MULBN words 17 x 15", 0x3d462f, num2TxV1, "000280008001017e0001708001017e957551", true, false},
	{"BN_mul limit: MULBN words 1024 x 1025", 0x3d462f, num2TxV1, "0002f81f8001017e000200208001017e957551", true, false},
	{"BN_mul limit: MULBN words 65536 x 65537", 0x3d462f, num2TxV1, "0003f8ff078001017e00030000088001017e957551", true, false},
	{"NUM2BIN: N2B a=empty n=0", 0x3d462f, num2TxV1, "000080a820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85587", true, false},
	{"NUM2BIN: N2B a=empty n=8", 0x3d462f, num2TxV1, "005880a820af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc87", true, false},
	{"NUM2BIN: N2B a=empty n=1000000", 0x3d462f, num2TxV1, "000340420f80a820d29751f2649b32ff572b5e0a9f541ea660a50f94ff0beedfb0b692b924cc802587", true, false},
	{"NUM2BIN: N2B a=80 n=0", 0x3d462f, num2TxV1, "01800080a820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85587", true, false},
	{"NUM2BIN: N2B a=80 n=8", 0x3d462f, num2TxV1, "01805880a820af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc87", true, false},
	{"NUM2BIN: N2B a=80 n=1000000", 0x3d462f, num2TxV1, "01800340420f80a820d29751f2649b32ff572b5e0a9f541ea660a50f94ff0beedfb0b692b924cc802587", true, false},
	{"NUM2BIN: N2B a=01 n=0", 0x3d462f, num2TxV1, "010100807551", false, false},
	{"NUM2BIN: N2B a=01 n=8", 0x3d462f, num2TxV1, "01015880a8207c9fa136d4413fa6173637e883b6998d32e1d675f88cddff9dcbcf331820f4b887", true, false},
	{"NUM2BIN: N2B a=01 n=1000000", 0x3d462f, num2TxV1, "01010340420f80a8202b6cd575cfc7e0bbe03f00035f6ed39d0fc0a475da25b1bcf8959f08ae06cc8e87", true, false},
	{"NUM2BIN: N2B a=81 n=0", 0x3d462f, num2TxV1, "018100807551", false, false},
	{"NUM2BIN: N2B a=81 n=8", 0x3d462f, num2TxV1, "01815880a820a43055f8bd67768dd864754d821ba89c8379418f1c93347514fad2169d9ee37887", true, false},
	{"NUM2BIN: N2B a=81 n=1000000", 0x3d462f, num2TxV1, "01810340420f80a82018bf7fe398f3f198763ba400955d7f1816a2a614f590044188d91e51ebeb4e9e87", true, false},
	{"NUM2BIN: N2B a=ff n=0", 0x3d462f, num2TxV1, "01ff00807551", false, false},
	{"NUM2BIN: N2B a=ff n=8", 0x3d462f, num2TxV1, "01ff5880a8206bd507b5c909007b8d4452795cf9871bb7eca2d73542a1dcf25f82f05e468bcf87", true, false},
	{"NUM2BIN: N2B a=ff n=1000000", 0x3d462f, num2TxV1, "01ff0340420f80a8201bf0b0689ee921740326f6dd5de27402fd1dd3cc1b716735bcd553d41152e0f187", true, false},
	{"NUM2BIN: N2B a=ff00 n=0", 0x3d462f, num2TxV1, "02ff0000807551", false, false},
	{"NUM2BIN: N2B a=ff00 n=8", 0x3d462f, num2TxV1, "02ff005880a820159754eeb1b8e153388279fd7cdf7c3224b6052d1b93d07e03beb4375a3a59f787", true, false},
	{"NUM2BIN: N2B a=ff00 n=1000000", 0x3d462f, num2TxV1, "02ff000340420f80a82042e3b90fd8540f72a8a6c1fe457ef0ff6203667369927c8b6a92d6b1f7d8732687", true, false},
	{"NUM2BIN: N2B a=ff80 n=0", 0x3d462f, num2TxV1, "02ff8000807551", false, false},
	{"NUM2BIN: N2B a=ff80 n=8", 0x3d462f, num2TxV1, "02ff805880a82022421732ac9725382013b471ed368483a85f523b74f3ce925884ed68ea22ed3087", true, false},
	{"NUM2BIN: N2B a=ff80 n=1000000", 0x3d462f, num2TxV1, "02ff800340420f80a8201c62f8804e83c047f260c45f50ea881c24511e09a25d8b778243d1bfee081ef087", true, false},
	{"NUM2BIN: N2B a=010000 n=0", 0x3d462f, num2TxV1, "0301000000807551", false, false},
	{"NUM2BIN: N2B a=010000 n=8", 0x3d462f, num2TxV1, "030100005880a8207c9fa136d4413fa6173637e883b6998d32e1d675f88cddff9dcbcf331820f4b887", true, false},
	{"NUM2BIN: N2B a=010000 n=1000000", 0x3d462f, num2TxV1, "030100000340420f80a8202b6cd575cfc7e0bbe03f00035f6ed39d0fc0a475da25b1bcf8959f08ae06cc8e87", true, false},
	{"NUM2BIN: N2B a=050080 n=0", 0x3d462f, num2TxV1, "0305008000807551", false, false},
	{"NUM2BIN: N2B a=050080 n=8", 0x3d462f, num2TxV1, "030500805880a8203533a639926376a36a2f9f8980a95bd65c0b2aa3456cfafa09098cfdb16b64a587", true, false},
	{"NUM2BIN: N2B a=050080 n=1000000", 0x3d462f, num2TxV1, "030500800340420f80a820748ddd4bc3251087952719d0fafa69f0d65161b7bf422237ca9e6bef6052839987", true, false},
	{"NUM2BIN: N2B a=00000080 n=0", 0x3d462f, num2TxV1, "04000000800080a820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85587", true, false},
	{"NUM2BIN: N2B a=00000080 n=8", 0x3d462f, num2TxV1, "04000000805880a820af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc87", true, false},
	{"NUM2BIN: N2B a=00000080 n=1000000", 0x3d462f, num2TxV1, "04000000800340420f80a820d29751f2649b32ff572b5e0a9f541ea660a50f94ff0beedfb0b692b924cc802587", true, false},
	{"NUM2BIN: N2B a=123456789a n=0", 0x3d462f, num2TxV1, "05123456789a00807551", false, false},
	{"NUM2BIN: N2B a=123456789a n=8", 0x3d462f, num2TxV1, "05123456789a5880a820d0098694be58e456a2f0356dd2e23b1f3bdb51693c9d12907caf4f816d0bef7a87", true, false},
	{"NUM2BIN: N2B a=123456789a n=1000000", 0x3d462f, num2TxV1, "05123456789a0340420f80a820589f4ab7f0936ae53edde0d63a1081904acdc71ef04c21815c06a79ee94ea19d87", true, false},
	{"NUM2BIN: N2B a=123456789a80 n=0", 0x3d462f, num2TxV1, "06123456789a8000807551", false, false},
	{"NUM2BIN: N2B a=123456789a80 n=8", 0x3d462f, num2TxV1, "06123456789a805880a82030cb0252a8a8924f50bd1d179a4946e064918986fb00358a757ccb0f2f17cfe887", true, false},
	{"NUM2BIN: N2B a=123456789a80 n=1000000", 0x3d462f, num2TxV1, "06123456789a800340420f80a82050d212df8c65a91037271574b12c7d9e05172e1c3f637bf8459f4e59e514639c87", true, false},
	{"NUM2BIN: N2B a=7f00000000 n=0", 0x3d462f, num2TxV1, "057f0000000000807551", false, false},
	{"NUM2BIN: N2B a=7f00000000 n=8", 0x3d462f, num2TxV1, "057f000000005880a820d3042cd79a29377cd5f9ce98d7152848ebfd2ecd55da46dd28785c753c0c612d87", true, false},
	{"NUM2BIN: N2B a=7f00000000 n=1000000", 0x3d462f, num2TxV1, "057f000000000340420f80a820cef35bd2105aeff16598fea84f87b1243b493c65b23258103334527fec59628c87", true, false},
	{"large operands: BIG MUL near-equal dense (BN limit) |a|=9000000B |b|=8999995B", 0x3d462f, num2TxV1, "1d5e45b4bab2a25f1b7adad89346a3daac508d77df98af47313ce320ea50767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41f068a41ae939cb1dea15966c81d0193f380ea4dafd24aaef3bcd11e78b4ea77767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b486259fdf6a03f25083505e71bc5b0a370bb76d437f242489c5520c443dcf6788ce290b4415e36f767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48601757e1d2d434b811c73a60a92752f9fef8b817ffaf687f05eb6c37e1d7507d0cd767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043a548900b41fa109a59db484f5200f1dbf7c4f253e675b3cb0cb1bbe1cb66497874beba88a767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043a548900b4862561495127088eda88dd844fcfdec85d45284669eb0aa1a01f0b9ddf8a304f3da6328889242f767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043a548900b486010e7e957551", false, true},
	{"large operands: BIG MUL 1048577x1048576 words dense (BN limit) |a|=8388609B |b|=8388608B", 0x3d462f, num2TxV1, "1dcbc73379e7826736c72ec9ba9f28c772807e193143a2aa39b43cd6a8c2767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e0400008000b41fe7cba5b46217448d2c3a9615e1513166aca2c4317c5256d7af50bfe6338461767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e0400008000b48625a0f8b7f41becf3efffd404518d87f1d14b42e82fe5efaa964f653d775af70adbbd090a5f62767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e0400008000b48601217e1d47bac857e692a15a7eab49c28d1698c4b0048f392ef485abe25c60f283767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e03ffff7fb41fad385b796cd297f060249b914f39bfc514d4827f75c70a7590261c1d05c25b767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e03ffff7fb486254a652e751297d7cfad7e1556747dc8344ac1642a41a01736d0e863d0d3162e5122b97dc8e6767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e03ffff7fb48601787e957551", false, true},
	{"large operands: BIG MUL unequal |a|=9000000B |b|=100B", 0x3d462f, num2TxV1, "1dfffcba3630b111ba196145677375219420017d5f10d7084e003e1e467c767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41fcfac639a52063d38842bfd43c427b90fa2ac540dcfbf78ac72823d47b7d0fa767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48625417b86b559c9beb7fec548a384de78052d54bc90a604a0e3a89c02f1b25304ad55b075fd01767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48601957e1df8d9258032476e6cd1fa8db7e6aefb79eeab9a6416ecea0de65afb0037767e767e0163b41f051b64ea097b02632b8686bd7b269a910cc7e29aa4a9dd336ab604b0d56aed767e767e0163b4862527bc64cea162bab183a65bcb038151b0883cc97983a22f3b942fb7e0f36743a0744bfd364c767e767e0163b48601257e95a82095a3774cd7c2872fffd0e1bc25e5ff953a6be12ccafab0ff99d14493e6bab11a87", true, true},
	{"large operands: BIG MUL unequal |a|=9000000B |b|=1000B", 0x3d462f, num2TxV1, "1db9cf07bfd594fbefa61de30a645da0a5275cbf15b6c16b168282377486767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41f35497e57369b87ea21f1b80803124e2a58434c6b6af4d5cae32d04405a28a6767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b4862516e03ae28eb6f3345d98b4bf220f16ed559fac1286cf83579e5bbf265b79154bb90074a332767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48601887e1d4d406d091bf3d08ab5cc58a03dfdad439a5cd5c8df507c5f86e3e62842767e767e767e767e767e767e02e703b41fd2439c65e9e7d63ad5436a1ac76b0acd6d1aaa7bcd5ef7109aae766d133714767e767e767e767e767e767e02e703b48625c9895590e1e19894aaa9c40c6f466f05ac8f9166cb59aa4e4e008fa1ef4c06d5a865522a17767e767e767e767e767e02e703b48601247e95a820ebf64d705792c9b3fd50816623422a892ebd5db7761201118e5520613147f27287", true, true},
	{"large operands: BIG DIV divisor 100B |a|=9000000B |b|=100B", 0x3d462f, num2TxV1, "1d12d23b284bb43c68448a1add06d15ac344de3dd141779ac0c82350be71767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41fd9f0bb919c72f0a02c291d1a551393b256c0658be5dade23ec676e1be553c4767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48625fce7ebbfd0739fc4fa4e69e85325cb4fcb64db2da124415640d361d7239dd03fb560f55dbb767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48601797e1d5a3f795ed283b4a06e95dfa086f505b88d0c0513aba3f8f1731261a405767e767e0163b41fff7a34c43b19945d12cdcda7ebf33f86216648ec4262f9a58b3dd3e087fb4d767e767e0163b48625a945f9ef27256587cb8c7a791ccf48664cd9c0fa89f76e1e4c9bc4dcfd49b33ea54ed7189f767e767e0163b48601ca7e96a82053a694f6c77b2ea33da578aa53ec0107823a3cc991f88fd4b8cb5c9f7578203f87", true, true},
	{"large operands: BIG DIV divisor 8999980B |a|=9000000B |b|=8999980B", 0x3d462f, num2TxV1, "1dbd128b940c464fdc65f0c194bc8eaba7111c29a77bd0577143c511d6c2767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41f9481146535b4e51d3ef95debd0b03f29df191e5f67c08c67fb52c86409c8f8767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48625aadc0b4d21a9d1b3f301ccc31d9c4dbc8d9b853636ae85b1bfec6650e3d52b0382221e91ed767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b486014d7e1db9c41c2dca746159b672c5f0e92e5a98124a6b2d62163d300da9494fc4767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e042b548900b41fa1cd2844fc0cbf7514da76697a4d5455edf171af703126561ae3e29cd8e506767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e042b548900b4862502d46c810475c44d2d6086a0e7babb7144cb1b6d64a35d9793e2afc44b654ceddb1bdf9bad767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e042b548900b486019b7e96a820181f2c016cb7997e2b3ce6c2c0be42af788a97445cc33530b25f909d41e8acfb87", true, true},
	{"large operands: BIG DIV divisor 9000005B |a|=9000000B |b|=9000005B", 0x3d462f, num2TxV1, "1d9826d411847203ad5753a3a9d231b77d400cb30cd7e254fb8c8d3ad4e7767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41f0c386836e6db70b0f7693a9085813dd53831617b1e72f23b8ee08ebe307bef767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b486257636eaf7d4c7f745b4e2761ea17df3af45ea11eab7ceba4e5b3dc1ac2d45f3f3705e8e92dd767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48601137e1d2b81b03365f496e6e3128e372724686d49e1dc57f90b56ad36122d6aeb767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e0444548900b41fafd91317c90282de76fb54b548f2d5ca2a4032519b6fa5e5ee4744fedfbb38767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e0444548900b48625c5a1b1f9fed349ca7d9a5794821d0c803aad224a984e80289e1441f6bf2af5198254c8b556767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e0444548900b48601947e96a820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85587", true, true},
	{"large operands: BIG MOD divisor 100B |a|=9000000B |b|=100B", 0x3d462f, num2TxV1, "1deee687fdfc174f8f7a31dea90ef0986846cbd993d0bcd6dac331ae50f7767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41f78eb9d40eecf91efbad16bdf66bdafd3ddcb198c659e7b9ecf33f1d571a237767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48625f4ab3cc7e4d7e3351ef18506b221880356c99068197460e5103ccd266867cedb6a5ba64a27767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48601ed7e1db8944ec8aec251fd74000b20feff78ae3a2c7c37265480787d9c04f40b767e767e0163b41f7a7315d0c999692538d22788db6993bfabdbe5578b8a0a4fe38045310ded1f767e767e0163b486252e8d8568c4fa73776c09a8d9529de9cb6058015745782c1a9435b1a9cd899ef6d0ead63a93767e767e0163b48601097e97a8201d344bfaf3a5996e8ad064ec27a7be0c1f86586ea32aa68364e34cf3f42e021e87", true, true},
	{"large operands: BIG MOD divisor 8999980B |a|=9000000B |b|=8999980B", 0x3d462f, num2TxV1, "1d037140c5913f1092ad9fa235dbcc930d2b590fd6ed6ba876d3aa3a1222767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41f83a489f02e5d0621962d8d7d355ed4265c0097e5c9902b0baf4eceb01a0fa1767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b4862522bc99381862832236ae48d4e369887e3c9039a54f6e681079849e4c05520684f3fda17cf9767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b486014a7e1d72771fc284fb971ce79ab15b40340fc3894fcaeccf863d71cee079435f767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e042b548900b41ffba4bc1dfbcfec8dc00cb56867121a741d5f6ed5accfe8634fcd9d5a783742767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e042b548900b48625dd4ae3e0a1d29511fc4e2753ce6d8828abe31da6f6982dea29ad929b3584b5c068f69639cd767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e042b548900b48601827e97a820bba34d048408f172ea8b0b9a4ab2e64bf9717032b35e6a3084f89c9947cdd2c987", true, true},
	{"large operands: BIG MOD divisor 9000005B |a|=9000000B |b|=9000005B", 0x3d462f, num2TxV1, "1dadbdb890995597ae0f934a1dfe7c5fbd77c9c6a4db8443a99c371c148b767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41f7430ed83b162481f8d69f7742e255cc41f0bcdd386c2b4b5593733ac9e1017767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48625c30a3054ebafb780e1bf905088ea116f3a2812f67cfa23482e83e21d0903e684015214a03d767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b486011c7e1d912952a451016165c11b72652a5b1cf424df50070260789f1cfd5ab189767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e0444548900b41f653167016a0c10c5fdeb2c120c2c611dbde68033c01011166458f7d3b34499767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e0444548900b486257bcff6f85dd113e718c3294088c0ec78f02d02e87c68bfd5b74c184c88a49c68f6369fc1e3767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e0444548900b48601b37e97a82038f8b0e069c116f4a8a497276b5155881c6ad67caa3910a7dca2357b66ce895287", true, true},
	{"large operands: BIG ADD equal-len |a|=9000000B |b|=9000000B", 0x3d462f, num2TxV1, "1dad4e69464bf3d7ea18432f2a75d41ab69ff7ce80177ab641ec303cfd27767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41f803beafd45999e58e4471d0f2744b8b816fac7a2c59bc980ba49270e96c382767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48625fffba62855aa673fd3600a72aeebab6dc4e9d753eac513ae78aade4cf2e84bf87768186501767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b486011a7e1d0bdf60cc77a11d1f9d01e4776a0e6023cc73875816765caa7d0bcdbe76767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41fab0a6745e6d4846795528662dec43267c098aa0b616c4fed6fc5915e9635d9767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48625d809ab3fed09bb8f2bac8a8f4335cb0c344116fdc4545b1d9394cc5a8977d0fef23adf0062767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48601017e93a8206118945d7fa062db15eaa92de306523f9e86577c3ff8dd49f5fec72bf9ad6f6e87", true, true},
	{"large operands: BIG ADD unequal |a|=9000000B |b|=100B", 0x3d462f, num2TxV1, "1d578110fdbe833041745003db9aae33d53657bdf03891537aa4018a1aeb767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41f2a49b887f06b08d35b691777c360ed6454e76453e9d58c5ae8d0f7ef571816767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48625afa22dec6b66ce2b967a39d2ca0e47f6dd11f3ed79ce1f3ad3dbcfea10fdbcf4ad8ee8c116767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48601c57e1d58c28a26241868feac55f87c87273a2161ba610aa78847465aa2c02de6767e767e0163b41fb683b9738192923da5826b6e0f9f1d88c1e0022d17c3f997c3be91c02929cd767e767e0163b486254343c5e7907c86764135906b0eb22562dcae4ffa137f08e460ec8a2696b2ec18548d0672f5767e767e0163b486015c7e93a820ad45a442247a3c7a78fcfa7ea3410241ef51411e51a0d58b9da821399de2991b87", true, true},
	{"large operands: BIG SUB equal-len |a|=9000000B |b|=9000000B", 0x3d462f, num2TxV1, "1d6b6c4568ab099b9a408bbd390d7a26846b7381b03c864aea3bc3b38d88767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41faa485f58685da1dc2f436617fb645ac992722260d874d2acbe9f9576f79b24767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48625b6fa6d52f61e9e298f69c0bef10f5bc2df7c5502db4e12a7842e4b8156ba2b1aaed77417e1767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48601337e1d4f85d5a55e3fcffef672a0d110de80dde8f1cf338844e3655e89c9eb8c767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41ffe210a5cf350f44f36ac5d9369a21406feffbe07a598dffec2214463474f65767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48625da1e3b0b2ee46fd1ed6e0de78e236af6b39b0bcd836f0bbfd63107a4c1cbc9c2efe06d5863767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48601757e94a820ad005f0ef9c99583ff931b5e1f2939b87f4e0a65e487bb55e152ca09ff8b71ca87", true, true},
	{"large operands: BIG SUB unequal |a|=9000000B |b|=100B", 0x3d462f, num2TxV1, "1d846da9b8217599446f231d800f87ddf8d0807e9d8d11097c3f8f435088767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41fee808aa4cf95d2a865213c459287d7071f24e7377b30e85226fc4dec9f1a55767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48625679ea0bfbf8291142cfce1296ac03d01ca71326c5929344aa07b83be65fd51c620388d664d767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48601dc7e1d7ed845791f56bf297a5b9a8052f04c86bad9f8b500ec1f1add1a26f542767e767e0163b41f0a98037a4f5b22104e7f340273bfbcc7270e19ec920782668d350dbd791e52767e767e0163b48625e4f24cca2a6224b63d90dc0a20d36c2510a398833f733afb9a8a4244e29f437808fa42cea8767e767e0163b48601737e94a8204d8561b1a1863507b2502aa6b1379bf17ee808d6469ba2333a4c1b5813a777aa87", true, true},
	{"large operands: BIG LSHIFTNUM n=limit+2 |a|=9000000B |b|=4B", 0x3d462f, num2TxV1, "1d1573d484e95f74eef1ff806b2294bbda7af5a2c06ae275616136c6a9cc767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41f751f1f97cfe9f166820ca9eb57342ec56467b651134de18b417993f1710cbe767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48625eba956c150798afab841706fe37a18c17211f1cb59bcaacdb13d8a9f659a0f5e9cfe9bc1cb767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48601307e04029ef70ab67551", false, true},
	{"large operands: BIG LSHIFTNUM n=limit+7 |a|=9000000B |b|=4B", 0x3d462f, num2TxV1, "1d1573d484e95f74eef1ff806b2294bbda7af5a2c06ae275616136c6a9cc767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41f751f1f97cfe9f166820ca9eb57342ec56467b651134de18b417993f1710cbe767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48625eba956c150798afab841706fe37a18c17211f1cb59bcaacdb13d8a9f659a0f5e9cfe9bc1cb767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48601307e04079ef70ab67551", false, true},
	{"large operands: BIG LSHIFTNUM n=limit+8 |a|=9000000B |b|=4B", 0x3d462f, num2TxV1, "1d1573d484e95f74eef1ff806b2294bbda7af5a2c06ae275616136c6a9cc767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41f751f1f97cfe9f166820ca9eb57342ec56467b651134de18b417993f1710cbe767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48625eba956c150798afab841706fe37a18c17211f1cb59bcaacdb13d8a9f659a0f5e9cfe9bc1cb767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48601307e04089ef70ab67551", false, true},
	{"large operands: BIG LSHIFTNUM n=rand |a|=9000000B |b|=4B", 0x3d462f, num2TxV1, "1d1573d484e95f74eef1ff806b2294bbda7af5a2c06ae275616136c6a9cc767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41f751f1f97cfe9f166820ca9eb57342ec56467b651134de18b417993f1710cbe767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48625eba956c150798afab841706fe37a18c17211f1cb59bcaacdb13d8a9f659a0f5e9cfe9bc1cb767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48601307e0444ed9701b6a8207553301b7eefc21606bcf77d9fc8576276f557a8e76de91ba8038faad064263287", true, true},
	{"large operands: BIG RSHIFTNUM n=1 |a|=9000000B |b|=1B", 0x3d462f, num2TxV1, "1d019ebc2a6b9378af6e5faebadcf5fc3a94366c79fcee6161426d201fd8767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41f79751b216fc28caf15bcdead41d5698d11339af0b8f415f94e7774b6343660767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48625fc7799742bafcda22964254c25e4f5a375350e2eda7a429b6f5b55bfd9c66c225410756c1a767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48601e47e51b7a82060d7b711843fca5dfe2b88f89a330bedf742eb6883cfe109429e62afa0e747d987", true, true},
	{"large operands: BIG RSHIFTNUM n=25413046 |a|=9000000B |b|=4B", 0x3d462f, num2TxV1, "1d019ebc2a6b9378af6e5faebadcf5fc3a94366c79fcee6161426d201fd8767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41f79751b216fc28caf15bcdead41d5698d11339af0b8f415f94e7774b6343660767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48625fc7799742bafcda22964254c25e4f5a375350e2eda7a429b6f5b55bfd9c66c225410756c1a767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48601e47e04b6c58301b7a820f125a371dd088c96e582a608ff7364aedf894f1214ea58aa0b9a87b97bfd797587", true, true},
	{"large operands: BIG RSHIFTNUM n=71999997 |a|=9000000B |b|=4B", 0x3d462f, num2TxV1, "1d019ebc2a6b9378af6e5faebadcf5fc3a94366c79fcee6161426d201fd8767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41f79751b216fc28caf15bcdead41d5698d11339af0b8f415f94e7774b6343660767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48625fc7799742bafcda22964254c25e4f5a375350e2eda7a429b6f5b55bfd9c66c225410756c1a767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48601e47e04fda14a04b7a8205ee0dd4d4840229fab4a86438efbcaf1b9571af94f5ace5acc94de19e98ea9ab87", true, true},
	{"large operands: BIG RSHIFTNUM n=72000100 |a|=9000000B |b|=4B", 0x3d462f, num2TxV1, "1d019ebc2a6b9378af6e5faebadcf5fc3a94366c79fcee6161426d201fd8767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b41f79751b216fc28caf15bcdead41d5698d11339af0b8f415f94e7774b6343660767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48625fc7799742bafcda22964254c25e4f5a375350e2eda7a429b6f5b55bfd9c66c225410756c1a767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e043f548900b48601e47e0464a24a04b7a820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85587", true, true},
	{"large operands: BIG MUL sparse near-equal |a|=1000000B |b|=1000000B", 0x3d462f, num2TxV1, "00033f420f8001017e00033f420f8001817e95a820d0a0879f433c0d14b12ad073dbc2f65f7f0176bfbef9424f26cab6d5f1eed5ea87", true, false},
	{"large operands: BIG ADD sparse |a|=1000000B |b|=1000000B", 0x3d462f, num2TxV1, "00033f420f8001017e00033f420f8001817e93a820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85587", true, false},
	{"large operands: BIG DIV sparse |a|=1000000B |b|=1000000B", 0x3d462f, num2TxV1, "00033f420f8001017e00033f420f8001817e96a820591b7cc95037822dec5a4d593a2e2e8b19c07ddd2570e5699003d17f14c440a687", true, false},
	{"large operands: BIG MUL sparse near-equal |a|=4194304B |b|=4194304B", 0x3d462f, num2TxV1, "0003ffff3f8001017e0003ffff3f8001817e95a820c7303e1f8a2d28e8e7cbfa6d408e5ab11ce5d855b938ae40fa40fd6791c6068187", true, true},
	{"large operands: BIG ADD sparse |a|=4194304B |b|=4194304B", 0x3d462f, num2TxV1, "0003ffff3f8001017e0003ffff3f8001817e93a820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85587", true, false},
	{"large operands: BIG DIV sparse |a|=4194304B |b|=4194304B", 0x3d462f, num2TxV1, "0003ffff3f8001017e0003ffff3f8001817e96a820591b7cc95037822dec5a4d593a2e2e8b19c07ddd2570e5699003d17f14c440a687", true, true},
	{"large operands: BIG MUL sparse near-equal |a|=8388608B |b|=8388608B", 0x3d462f, num2TxV1, "0003ffff7f8001017e0003ffff7f8001817e95a82009b0be89e872d37df9d131c29513d6ddc1dbe5d3b48594c28bfa37a108330a3587", true, true},
	{"large operands: BIG ADD sparse |a|=8388608B |b|=8388608B", 0x3d462f, num2TxV1, "0003ffff7f8001017e0003ffff7f8001817e93a820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85587", true, false},
	{"large operands: BIG DIV sparse |a|=8388608B |b|=8388608B", 0x3d462f, num2TxV1, "0003ffff7f8001017e0003ffff7f8001817e96a820591b7cc95037822dec5a4d593a2e2e8b19c07ddd2570e5699003d17f14c440a687", true, true},
	{"large operands: BIG MUL sparse near-equal |a|=8388609B |b|=8388609B", 0x3d462f, num2TxV1, "0004000080008001017e0004000080008001817e957551", false, false},
	{"large operands: BIG ADD sparse |a|=8388609B |b|=8388609B", 0x3d462f, num2TxV1, "0004000080008001017e0004000080008001817e93a820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85587", true, false},
	{"large operands: BIG DIV sparse |a|=8388609B |b|=8388609B", 0x3d462f, num2TxV1, "0004000080008001017e0004000080008001817e96a820591b7cc95037822dec5a4d593a2e2e8b19c07ddd2570e5699003d17f14c440a687", true, true},
}

// TestGHSANum2CatSizeLimitByEra checks that OP_CAT limits its result to 520
// bytes only for outputs created before Genesis, like node's OP_CAT
// (interpreter.cpp:1699-1702).
func TestGHSANum2CatSizeLimitByEra(t *testing.T) {
	t.Parallel()

	// <260 bytes> <261 bytes> OP_CAT OP_SIZE <521> OP_EQUAL
	lock := make([]byte, 0, 3+260+3+261+6)
	lock = append(lock, script.OpPUSHDATA2, 0x04, 0x01)
	lock = append(lock, make([]byte, 260)...)
	lock = append(lock, script.OpPUSHDATA2, 0x05, 0x01)
	lock = append(lock, make([]byte, 261)...)
	lock = append(lock, script.OpCAT, script.OpSIZE, 0x02, 0x09, 0x02, script.OpEQUAL)
	unlock := []byte{script.Op1}

	for _, tc := range []struct {
		name  string
		flags scriptflag.Flag
		valid bool
	}{
		{"pre-Genesis", 0, false},
		{"post-Genesis", scriptflag.UTXOAfterGenesis, true},
		{"post-Chronicle", scriptflag.UTXOAfterGenesis | scriptflag.UTXOAfterChronicle, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := NewEngine().Execute(
				WithScripts(script.NewFromBytes(lock), script.NewFromBytes(unlock)),
				WithFlags(tc.flags),
			)
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
