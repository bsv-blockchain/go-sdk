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
