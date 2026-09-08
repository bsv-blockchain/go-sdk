package transaction

import (
	"encoding/hex"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
)

// benchBeef parses the multi-transaction V2 BEEFSet fixture once, outside the
// timer, for the Bytes()/AtomicBytes() serialization benchmarks.
func benchBeef(b *testing.B) *Beef {
	b.Helper()
	raw, err := hex.DecodeString(BEEFSet)
	if err != nil {
		b.Fatal(err)
	}
	beef, err := NewBeefFromBytes(raw)
	if err != nil {
		b.Fatal(err)
	}
	return beef
}

// benchBeefSubjectTxID returns a txid of a transaction present in beef, for the
// AtomicBytes benchmark.
func benchBeefSubjectTxID(b *testing.B, beef *Beef) *chainhash.Hash {
	b.Helper()
	for _, bt := range beef.Transactions {
		if bt.Transaction != nil {
			return bt.Transaction.TxID()
		}
	}
	b.Fatal("no transaction in beef")
	return nil
}

func BenchmarkBeefBytes(b *testing.B) {
	beef := benchBeef(b)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := beef.Bytes(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBeefAtomicBytes(b *testing.B) {
	beef := benchBeef(b)
	txid := benchBeefSubjectTxID(b, beef)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := beef.AtomicBytes(txid); err != nil {
			b.Fatal(err)
		}
	}
}
