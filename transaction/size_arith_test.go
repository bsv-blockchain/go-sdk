package transaction

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/stretchr/testify/require"
)

func sizeTestTx(nIn, nOut, inScriptLen, outScriptLen int) *Transaction {
	tx := &Transaction{Version: 1, LockTime: 0}
	var txid chainhash.Hash
	for j := range nIn {
		tx.Inputs = append(tx.Inputs, &TransactionInput{
			SourceTXID:       &txid,
			SourceTxOutIndex: uint32(j), SequenceNumber: 0xffffffff,
			UnlockingScript: script.NewFromBytes(make([]byte, inScriptLen)),
		})
	}
	for j := range nOut {
		tx.Outputs = append(tx.Outputs, &TransactionOutput{
			Satoshis: uint64(1000 + j), LockingScript: script.NewFromBytes(make([]byte, outScriptLen)),
		})
	}
	return tx
}

// TestSizeMatchesSerializedLength locks the invariant that the arithmetic
// Size() equals the length of the fully serialized transaction across input,
// output and script-length VarInt boundaries.
func TestSizeMatchesSerializedLength(t *testing.T) {
	cases := []struct {
		name                      string
		nIn, nOut                 int
		inScriptLen, outScriptLen int
	}{
		{"empty", 0, 0, 0, 0},
		{"1in-1out-small", 1, 1, 25, 25},
		{"4in-4out-p2pkh", 4, 4, 107, 25},
		{"input-script-varint253", 1, 1, 253, 25},
		{"input-script-varint65536", 1, 1, 65536, 25},
		{"output-script-varint253", 1, 1, 25, 253},
		{"count-varint-boundary", 300, 300, 8, 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx := sizeTestTx(tc.nIn, tc.nOut, tc.inScriptLen, tc.outScriptLen)
			require.Equal(t, len(tx.Bytes()), tx.Size(),
				"Size() must equal len(Bytes())")
		})
	}
}

// TestSizeNilUnlockingScript verifies inputs with a nil unlocking script are
// sized identically to how Bytes() serializes them (empty script).
func TestSizeNilUnlockingScript(t *testing.T) {
	var txid chainhash.Hash
	tx := &Transaction{
		Version: 1,
		Inputs: []*TransactionInput{{
			SourceTXID:       &txid,
			SourceTxOutIndex: 0,
			SequenceNumber:   0xffffffff,
		}},
		Outputs: []*TransactionOutput{{
			Satoshis:      1000,
			LockingScript: script.NewFromBytes(make([]byte, 25)),
		}},
	}
	require.Equal(t, len(tx.Bytes()), tx.Size())
}

// TestBytesForSigHashEqualsBytes locks the invariant (relied on by OutputsHash)
// that an output's sighash serialization is byte-identical to Bytes().
func TestBytesForSigHashEqualsBytes(t *testing.T) {
	for _, scriptLen := range []int{0, 25, 253, 65536} {
		out := &TransactionOutput{
			Satoshis:      123456,
			LockingScript: script.NewFromBytes(make([]byte, scriptLen)),
		}
		require.Equal(t, out.Bytes(), out.BytesForSigHash(),
			"BytesForSigHash must equal Bytes (scriptLen=%d)", scriptLen)
	}
}

// TestParseRoundTripVarIntBoundaries locks that a transaction serialized with
// multi-byte CompactSize VarInts — for the input count, output count and script
// lengths — parses back byte-identically. It deterministically exercises the
// 0xfd (2-byte) and 0xfe (4-byte) VarInt read branches and the guarded slice
// pre-size against large counts, none of which the fixed P2PKH benchmark
// fixtures or the golden vectors reach.
func TestParseRoundTripVarIntBoundaries(t *testing.T) {
	cases := []struct {
		name                      string
		nIn, nOut                 int
		inScriptLen, outScriptLen int
	}{
		// 253 crosses the 1-byte -> 3-byte (0xfd) VarInt boundary for both the
		// element counts and the script lengths.
		{"count-and-script-varint253", 253, 253, 253, 253},
		// 65536 crosses the 3-byte -> 5-byte (0xfe) boundary for a script length.
		{"script-varint65536", 1, 1, 65536, 25},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx := sizeTestTx(tc.nIn, tc.nOut, tc.inScriptLen, tc.outScriptLen)
			raw := tx.Bytes()

			parsed, err := NewTransactionFromBytes(raw)
			require.NoError(t, err)
			require.Len(t, parsed.Inputs, tc.nIn)
			require.Len(t, parsed.Outputs, tc.nOut)
			require.Equal(t, raw, parsed.Bytes(), "parse->serialize must be byte-identical")
		})
	}
}

// TestSerializedSizeMatchesAllModes locks that the arithmetic serializedSize
// used to pre-size the serialization buffer matches the actual byte length
// produced by toBytesHelper in every mode: raw, cleared-input (signing), and
// extended (EF). An over- or under-estimate would silently reintroduce a buffer
// reallocation.
func TestSerializedSizeMatchesAllModes(t *testing.T) {
	tx := sizeTestTx(3, 2, 50, 25)
	require.Equal(t, len(tx.Bytes()), tx.serializedSize(0, nil, false), "raw")

	lockingScript := make([]byte, 40)
	require.Equal(t, len(tx.BytesWithClearedInputs(1, lockingScript)),
		tx.serializedSize(1, lockingScript, false), "cleared-input")

	// Extended format needs each input's source output, which benchTx wires up
	// via SourceTransaction.
	ext := benchTx(3, benchTx(0), benchTx(1))
	efBytes, err := ext.EF()
	require.NoError(t, err)
	require.Equal(t, len(efBytes), ext.serializedSize(0, nil, true), "extended")
}
