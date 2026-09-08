package transaction_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// serializationTestTxs returns transactions covering the serialization edge
// cases: empty, an input with a nil unlocking script, and signed transactions
// of several input counts.
func serializationTestTxs(tb testing.TB) map[string]*transaction.Transaction {
	tb.Helper()

	nilScript := transaction.NewTransaction()
	var h chainhash.Hash
	nilScript.Inputs = append(nilScript.Inputs, &transaction.TransactionInput{
		SourceTXID:     &h,
		SequenceNumber: 0xffffffff,
	})
	nilScript.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1,
		LockingScript: script.NewFromBytes([]byte{0x51}),
	})

	txs := map[string]*transaction.Transaction{
		"empty":                transaction.NewTransaction(),
		"nil-unlocking-script": nilScript,
	}
	for _, nIn := range []int{0, 1, 4, 16} {
		txs[fmt.Sprintf("inputs=%d", nIn)] = benchP2PKHTx(tb, nIn)
	}
	return txs
}

// TestAppendBytesMatchesBytes verifies AppendBytes appends the same bytes as
// Bytes() regardless of the destination (nil, exact-capacity, or a non-empty
// prefix that must be preserved).
func TestAppendBytesMatchesBytes(t *testing.T) {
	for name, tx := range serializationTestTxs(t) {
		t.Run(name, func(t *testing.T) {
			want := tx.Bytes()

			require.Equal(t, want, tx.AppendBytes(nil))
			require.Equal(t, want, tx.AppendBytes(make([]byte, 0, tx.Size())))

			prefix := []byte{0xDE, 0xAD, 0xBE, 0xEF}
			got := tx.AppendBytes(append([]byte(nil), prefix...))
			require.Equal(t, append(append([]byte(nil), prefix...), want...), got)
		})
	}
}

// TestWriteToMatchesBytes verifies WriteTo streams exactly Bytes() and reports
// the correct byte count.
func TestWriteToMatchesBytes(t *testing.T) {
	for name, tx := range serializationTestTxs(t) {
		t.Run(name, func(t *testing.T) {
			want := tx.Bytes()

			var buf bytes.Buffer
			n, err := tx.WriteTo(&buf)
			require.NoError(t, err)
			require.Equal(t, want, buf.Bytes())
			require.Equal(t, int64(len(want)), n)
		})
	}
}

// failWriter accepts limit total bytes, then fails; it returns any partial
// write alongside the error so WriteTo's error propagation can be exercised.
type failWriter struct {
	limit   int
	written int
}

var errWriteFull = errors.New("failWriter full")

func (fw *failWriter) Write(p []byte) (int, error) {
	remaining := fw.limit - fw.written
	if remaining <= 0 {
		return 0, errWriteFull
	}
	if len(p) > remaining {
		fw.written += remaining
		return remaining, errWriteFull
	}
	fw.written += len(p)
	return len(p), nil
}

// TestWriteToPropagatesWriterError verifies WriteTo surfaces the writer's error
// when it fails at various offsets (version, input, output, near the end) and
// never reports writing more than the transaction's length.
func TestWriteToPropagatesWriterError(t *testing.T) {
	tx := benchP2PKHTx(t, 4)
	full := len(tx.Bytes())
	for _, limit := range []int{0, 4, 10, 46, full - 30, full - 15, full - 1} {
		n, err := tx.WriteTo(&failWriter{limit: limit})
		require.ErrorIs(t, err, errWriteFull, "limit=%d", limit)
		require.LessOrEqual(t, n, int64(full), "limit=%d", limit)
	}
}

// zeroWriter accepts no bytes and reports no error, to exercise WriteTo's
// io.ErrShortWrite guard (a partial write that never progresses).
type zeroWriter struct{}

func (zeroWriter) Write(p []byte) (int, error) { return 0, nil }

// TestWriteToShortWrite verifies WriteTo returns io.ErrShortWrite when the
// writer makes no progress rather than looping forever.
func TestWriteToShortWrite(t *testing.T) {
	tx := benchP2PKHTx(t, 1)
	_, err := tx.WriteTo(zeroWriter{})
	require.ErrorIs(t, err, io.ErrShortWrite)
}

// TestAppendBytesReuseZeroAlloc confirms AppendBytes into a reused,
// sufficiently-sized buffer performs no heap allocation.
func TestAppendBytesReuseZeroAlloc(t *testing.T) {
	tx := benchP2PKHTx(t, 16)
	buf := make([]byte, 0, tx.Size())
	allocs := testing.AllocsPerRun(200, func() {
		buf = tx.AppendBytes(buf[:0])
	})
	require.Zero(t, allocs, "AppendBytes into a reused buffer must not allocate")
}

// BenchmarkAppendBytesReuse measures serializing repeatedly into one reused
// buffer; contrast with BenchmarkSerializeRaw (tx.Bytes()), which allocates a
// fresh buffer every call.
func BenchmarkAppendBytesReuse(b *testing.B) {
	for _, nIn := range []int{1, 16, 64} {
		b.Run(fmt.Sprintf("inputs=%d", nIn), func(b *testing.B) {
			tx := benchP2PKHTx(b, nIn)
			buf := make([]byte, 0, tx.Size())
			b.ReportAllocs()
			for b.Loop() {
				buf = tx.AppendBytes(buf[:0])
			}
		})
	}
}

// BenchmarkWriteTo measures streaming serialization with no full-transaction
// buffer; contrast the B/op with BenchmarkSerializeRaw.
func BenchmarkWriteTo(b *testing.B) {
	for _, nIn := range []int{1, 16, 64} {
		b.Run(fmt.Sprintf("inputs=%d", nIn), func(b *testing.B) {
			tx := benchP2PKHTx(b, nIn)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := tx.WriteTo(io.Discard); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
