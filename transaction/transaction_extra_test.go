package transaction

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// errUnlockTemplate is an UnlockingScriptTemplate whose Sign always fails, used
// to drive the error paths of Transaction.Sign / SignUnsigned.
type errUnlockTemplate struct{}

func (errUnlockTemplate) Sign(*Transaction, uint32) (*script.Script, error) {
	return nil, errors.New("template sign failed")
}

func (errUnlockTemplate) EstimateLength(*Transaction, uint32) uint32 { return 0 }

// errFeeModel is a FeeModel whose ComputeFee always fails.
type errFeeModel struct{}

func (errFeeModel) ComputeFee(*Transaction) (uint64, error) {
	return 0, errors.New("compute fee failed")
}

// errLimitWrite is returned by limitWriter once its byte budget is exhausted.
var errLimitWrite = errors.New("limitWriter budget exhausted")

// limitWriter accepts limit total bytes and then fails, returning any partial
// write alongside the error so streaming error paths can be exercised.
type limitWriter struct {
	limit   int
	written int
}

func (lw *limitWriter) Write(p []byte) (int, error) {
	remaining := lw.limit - lw.written
	if remaining <= 0 {
		return 0, errLimitWrite
	}
	if len(p) > remaining {
		lw.written += remaining
		return remaining, errLimitWrite
	}
	lw.written += len(p)
	return len(p), nil
}

func TestNewTransactionFromHexInvalid(t *testing.T) {
	t.Parallel()
	_, err := NewTransactionFromHex("zzzz")
	require.Error(t, err)
}

func TestNewTransactionFromBytesTrailingData(t *testing.T) {
	t.Parallel()
	tx := NewTransaction()
	tx.AddOutput(&TransactionOutput{Satoshis: 1, LockingScript: &script.Script{}})
	raw := tx.Bytes()
	// Appending a trailing byte makes used != len(b).
	_, err := NewTransactionFromBytes(append(raw, 0x00))
	require.ErrorIs(t, err, ErrNLockTimeLength)
}

func TestTransactionReadFromTruncated(t *testing.T) {
	t.Parallel()
	ver := []byte{0x01, 0x00, 0x00, 0x00}
	tests := []struct {
		name string
		data []byte
	}{
		{name: "no-output-count", data: append(append([]byte{}, ver...), 0x00)},
		{name: "no-locktime-empty-tx", data: append(append([]byte{}, ver...), 0x00, 0x00)},
		{
			name: "extended-marker-then-eof",
			data: append(append([]byte{}, ver...), 0x00, 0x00, 0x00, 0x00, 0x00, 0xEF),
		},
		{
			name: "input-count-overflow",
			data: append(append([]byte{}, ver...), 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewTransactionFromBytes(tc.data)
			require.Error(t, err)
		})
	}
}

func TestTransactionReadFromInputParseError(t *testing.T) {
	t.Parallel()
	// version + inputCount(1) + 32 txid + 4 index + varint 0xFE FFFFFFFF (huge
	// script length). The count guard passes (41 bytes remain) but the per-input
	// script guard rejects the impossible length.
	data := make([]byte, 0, 46)
	data = append(data, 0x01, 0x00, 0x00, 0x00, 0x01)
	data = append(data, make([]byte, 32)...)    // txid
	data = append(data, 0x00, 0x00, 0x00, 0x00) // index
	data = append(data, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF)
	_, err := NewTransactionFromBytes(data)
	require.Error(t, err)
}

func validInputBytes() []byte {
	b := make([]byte, 0, 41)
	b = append(b, make([]byte, 32)...)    // txid
	b = append(b, 0x00, 0x00, 0x00, 0x00) // index
	b = append(b, 0x00)                   // empty unlocking script
	b = append(b, 0xFF, 0xFF, 0xFF, 0xFF) // sequence
	return b
}

func TestTransactionReadFromOutputStageErrors(t *testing.T) {
	t.Parallel()
	ver := []byte{0x01, 0x00, 0x00, 0x00}
	in := validInputBytes()

	base := func() []byte {
		b := append([]byte{}, ver...)
		b = append(b, 0x01) // inputCount = 1
		b = append(b, in...)
		return b
	}

	t.Run("output-count-eof", func(t *testing.T) {
		t.Parallel()
		_, err := NewTransactionFromBytes(base())
		require.Error(t, err)
	})

	t.Run("output-count-overflow", func(t *testing.T) {
		t.Parallel()
		b := base()
		b = append(b, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
		_, err := NewTransactionFromBytes(b)
		require.Error(t, err)
	})

	t.Run("output-parse-error", func(t *testing.T) {
		t.Parallel()
		b := base()
		b = append(b, 0x01)                         // outputCount = 1
		b = append(b, make([]byte, 8)...)           // satoshis
		b = append(b, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF) // huge script length
		_, err := NewTransactionFromBytes(b)
		require.Error(t, err)
	})

	t.Run("locktime-eof", func(t *testing.T) {
		t.Parallel()
		b := base()
		b = append(b, 0x01)               // outputCount = 1
		b = append(b, make([]byte, 8)...) // satoshis
		b = append(b, 0x00)               // empty locking script
		// no locktime bytes -> EOF
		_, err := NewTransactionFromBytes(b)
		require.Error(t, err)
	})
}

func TestTransactionsReadFromErrors(t *testing.T) {
	t.Parallel()

	t.Run("count-eof", func(t *testing.T) {
		t.Parallel()
		var tt Transactions
		_, err := tt.ReadFrom(bytes.NewReader(nil))
		require.Error(t, err)
	})

	t.Run("count-overflow", func(t *testing.T) {
		t.Parallel()
		var tt Transactions
		data := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		_, err := tt.ReadFrom(bytes.NewReader(data))
		require.Error(t, err)
	})

	t.Run("inner-tx-error", func(t *testing.T) {
		t.Parallel()
		var tt Transactions
		data := make([]byte, 0, 14)
		data = append(data, 0x01)                   // txCount = 1
		data = append(data, 0x01, 0x00, 0x00, 0x00) // version
		data = append(data, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
		_, err := tt.ReadFrom(bytes.NewReader(data))
		require.Error(t, err)
	})
}

func TestTransactionsReadFromRoundTrip(t *testing.T) {
	t.Parallel()
	tx := NewTransaction()
	tx.AddOutput(&TransactionOutput{Satoshis: 7, LockingScript: &script.Script{}})

	buf := new(bytes.Buffer)
	buf.Write([]byte{0x01}) // one transaction
	buf.Write(tx.Bytes())

	var tt Transactions
	_, err := tt.ReadFrom(buf)
	require.NoError(t, err)
	require.Len(t, tt, 1)
	assert.Equal(t, uint64(7), tt[0].Outputs[0].Satoshis)
}

func TestTransactionIsCoinbaseFalseCases(t *testing.T) {
	t.Parallel()

	t.Run("no-inputs", func(t *testing.T) {
		t.Parallel()
		tx := NewTransaction()
		assert.False(t, tx.IsCoinbase())
	})

	t.Run("nonzero-source-txid", func(t *testing.T) {
		t.Parallel()
		hash, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
		tx := NewTransaction()
		tx.AddInput(&TransactionInput{SourceTXID: hash, SourceTxOutIndex: 0, SequenceNumber: 0})
		assert.False(t, tx.IsCoinbase())
	})

	t.Run("zero-txid-but-not-max-index-or-seq", func(t *testing.T) {
		t.Parallel()
		tx := NewTransaction()
		tx.AddInput(&TransactionInput{SourceTXID: &chainhash.Hash{}, SourceTxOutIndex: 0, SequenceNumber: 0})
		assert.False(t, tx.IsCoinbase())
	})
}

func TestTransactionEFWithMissingSourceOutput(t *testing.T) {
	t.Parallel()
	// SourceTransaction is set but its output index is out of range and no
	// direct sourceOutput is supplied, so SourceTxOutput() returns nil while
	// EF()'s guard still passes -- exercising the zero-source-output serializer.
	src := NewTransaction() // no outputs
	tx := NewTransaction()
	tx.AddInput(&TransactionInput{
		SourceTXID:        src.TxID(),
		SourceTxOutIndex:  5,
		SourceTransaction: src,
		SequenceNumber:    DefaultSequenceNumber,
	})
	tx.AddOutput(&TransactionOutput{Satoshis: 1, LockingScript: &script.Script{}})

	ef, err := tx.EF()
	require.NoError(t, err)
	require.NotEmpty(t, ef)
}

func TestTransactionWriteToOutputCountError(t *testing.T) {
	t.Parallel()
	tx := NewTransaction()
	tx.AddInput(&TransactionInput{SourceTXID: &chainhash.Hash{}, SequenceNumber: DefaultSequenceNumber})
	tx.AddOutput(&TransactionOutput{Satoshis: 1, LockingScript: &script.Script{}})

	// 4 (version) + 1 (input count) + 41 (input) = 46 bytes written before the
	// output-count varint, which then fails.
	_, err := tx.WriteTo(&limitWriter{limit: 46})
	require.ErrorIs(t, err, errLimitWrite)
}

func TestTransactionSignSkipsNilTemplate(t *testing.T) {
	t.Parallel()
	tx := NewTransaction()
	tx.AddInput(&TransactionInput{SourceTXID: &chainhash.Hash{}, SequenceNumber: DefaultSequenceNumber})
	tx.AddOutput(&TransactionOutput{Satoshis: 1, LockingScript: &script.Script{}})
	require.NoError(t, tx.Sign())
}

func TestTransactionSignTemplateError(t *testing.T) {
	t.Parallel()

	build := func() *Transaction {
		tx := NewTransaction()
		tx.AddInput(&TransactionInput{
			SourceTXID:              &chainhash.Hash{},
			SequenceNumber:          DefaultSequenceNumber,
			UnlockingScriptTemplate: errUnlockTemplate{},
		})
		tx.AddOutput(&TransactionOutput{Satoshis: 1, LockingScript: &script.Script{}})
		return tx
	}

	require.Error(t, build().Sign())
	require.Error(t, build().SignUnsigned())
}

func TestTransactionSignFeeNotComputed(t *testing.T) {
	t.Parallel()
	tx := NewTransaction()
	tx.AddOutput(&TransactionOutput{Satoshis: 0, LockingScript: &script.Script{}, Change: true})
	require.Error(t, tx.Sign())
	require.Error(t, tx.SignUnsigned())
}

func TestAtomicBEEFMissingSource(t *testing.T) {
	t.Parallel()
	tx := NewTransaction()
	tx.AddInput(&TransactionInput{SourceTXID: &chainhash.Hash{}, SequenceNumber: DefaultSequenceNumber})
	tx.AddOutput(&TransactionOutput{Satoshis: 1, LockingScript: &script.Script{}})

	_, err := tx.AtomicBEEF(false)
	require.Error(t, err)

	// allowPartial skips the missing source rather than erroring.
	partial, err := tx.AtomicBEEF(true)
	require.NoError(t, err)
	require.NotEmpty(t, partial)
}

func TestNewTransactionFromBEEFErrors(t *testing.T) {
	t.Parallel()

	t.Run("atomic-hash-eof", func(t *testing.T) {
		t.Parallel()
		// hex.DecodeString keeps the length out of static analysis (io.ReadFull of
		// the 32-byte hash fails long before the beef[36:] reslice is reached).
		data, err := hex.DecodeString("01010101" + "00000000000000000000") // ATOMIC_BEEF + 10 bytes
		require.NoError(t, err)
		_, err = NewTransactionFromBEEF(data)
		require.Error(t, err)
	})

	t.Run("atomic-body-invalid", func(t *testing.T) {
		t.Parallel()
		data := make([]byte, 0, 38)
		data = append(data, le32(ATOMIC_BEEF)...)
		data = append(data, make([]byte, 32)...) // hash
		data = append(data, 0x00, 0x00)          // too-short body for readVersion
		_, err := NewTransactionFromBEEF(data)
		require.Error(t, err)
	})

	t.Run("unknown-version", func(t *testing.T) {
		t.Parallel()
		data, err := hex.DecodeString("00000000")
		require.NoError(t, err)
		_, err = NewTransactionFromBEEF(data)
		require.Error(t, err)
	})
}

func TestCalcInputSignatureHashLegacySingleOutOfRange(t *testing.T) {
	t.Parallel()
	// A single input with a source but no outputs, signed with SIGHASH_SINGLE
	// (legacy, no FORKID) yields the defaultHex sentinel unchanged.
	src := NewTransaction()
	src.AddOutput(&TransactionOutput{Satoshis: 1000, LockingScript: &script.Script{}})
	tx := NewTransaction()
	tx.AddInputFromTx(src, 0, nil)

	digest, err := tx.CalcInputSignatureHash(0, sighash.Single)
	require.NoError(t, err)
	assert.Equal(t, defaultHex, digest)
}

func TestCalcInputSignatureHashErrors(t *testing.T) {
	t.Parallel()
	tx := NewTransaction()
	tx.AddOutput(&TransactionOutput{Satoshis: 1, LockingScript: &script.Script{}})

	// Out-of-range input index, FORKID path.
	_, err := tx.CalcInputSignatureHash(5, sighash.All|sighash.ForkID)
	require.ErrorIs(t, err, ErrInputNoExist)

	_, err = tx.CalcInputSignatureHashWithCache(5, sighash.All|sighash.ForkID, nil)
	require.ErrorIs(t, err, ErrInputNoExist)
}

func TestCalcInputPreimageMissingSource(t *testing.T) {
	t.Parallel()
	tx := NewTransaction()
	tx.AddInput(&TransactionInput{SourceTXID: &chainhash.Hash{}, SequenceNumber: DefaultSequenceNumber})
	tx.AddOutput(&TransactionOutput{Satoshis: 1, LockingScript: &script.Script{}})

	_, err := tx.CalcInputPreimage(0, sighash.All|sighash.ForkID)
	require.ErrorIs(t, err, ErrEmptyPreviousTx)

	_, err = tx.CalcInputPreimageLegacy(0, sighash.All)
	require.ErrorIs(t, err, ErrEmptyPreviousTx)
}

func TestCalcInputPreimageLegacyNoInput(t *testing.T) {
	t.Parallel()
	tx := NewTransaction()
	_, err := tx.CalcInputPreimageLegacy(3, sighash.All)
	require.ErrorIs(t, err, ErrInputNoExist)
}
