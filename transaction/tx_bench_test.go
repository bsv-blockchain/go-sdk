package transaction_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	feemodel "github.com/bsv-blockchain/go-sdk/transaction/fee_model"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/bsv-blockchain/go-sdk/transaction/testdata"
)

// Benchmarks for the transaction hot paths a wallet exercises on every action:
// serializing to raw/extended bytes, deserializing them back, computing the
// signature preimage, signing a P2PKH input, and BEEF/EF round-tripping.
//
// The transaction shapes are built outside the timer; only the operation under
// test is measured. Serialize/deserialize/sighash benchmarks scale by input
// count, which dominates both the byte size and the per-input hashing work.

// benchWIF is a well-known throwaway key reused across benchmarks so key
// derivation stays out of the timer and results are comparable run to run.
const benchWIF = "KznvCNc6Yf4iztSThoMH6oHWzH9EgjfodKxmeuUGPq5DEX5maspS"

// benchInputSizes is the standard set of input counts serialize/deserialize
// benchmarks scale over.
var benchInputSizes = []int{1, 4, 16, 64}

// benchOutputs is the fixed number of P2PKH outputs benchP2PKHTx attaches; the
// benchmarks scale by input count, which dominates size and per-input hashing.
const benchOutputs = 2

// benchP2PKHTx builds a fully-signed transaction with nIn P2PKH inputs (each
// funded by a distinct source transaction so its SourceTxOutput is available
// for the sighash) and a fixed number of P2PKH outputs.
func benchP2PKHTx(tb testing.TB, nIn int) *transaction.Transaction {
	tb.Helper()

	priv, err := ec.PrivateKeyFromWif(benchWIF)
	require.NoError(tb, err)
	addr, err := script.NewAddressFromPublicKey(priv.PubKey(), true)
	require.NoError(tb, err)
	lock, err := p2pkh.Lock(addr)
	require.NoError(tb, err)
	unlock, err := p2pkh.Unlock(priv, nil)
	require.NoError(tb, err)

	tx := transaction.NewTransaction()
	for i := range nIn {
		src := transaction.NewTransaction()
		src.LockTime = uint32(i)
		src.AddOutput(&transaction.TransactionOutput{
			Satoshis:      100_000,
			LockingScript: lock,
		})
		tx.AddInputFromTx(src, 0, unlock)
	}
	for range benchOutputs {
		tx.AddOutput(&transaction.TransactionOutput{
			Satoshis:      1000,
			LockingScript: lock,
		})
	}
	require.NoError(tb, tx.Sign())
	return tx
}

// BenchmarkTxID measures TxID computation, which re-serializes the whole
// transaction on every call (transaction.go:265) — a candidate for caching.
func BenchmarkTxID(b *testing.B) {
	for _, n := range benchInputSizes {
		b.Run(fmt.Sprintf("inputs=%d", n), func(b *testing.B) {
			tx := benchP2PKHTx(b, n)

			b.ReportAllocs()
			for b.Loop() {
				_ = tx.TxID()
			}
		})
	}
}

// BenchmarkSerializeRaw measures raw (non-extended) serialization via Bytes.
func BenchmarkSerializeRaw(b *testing.B) {
	for _, n := range benchInputSizes {
		b.Run(fmt.Sprintf("inputs=%d", n), func(b *testing.B) {
			tx := benchP2PKHTx(b, n)

			b.ReportAllocs()
			for b.Loop() {
				_ = tx.Bytes()
			}
		})
	}
}

// BenchmarkSerializeExtended measures extended-format (EF) serialization, which
// walks each input's source output through toBytesHelper (transaction.go:385).
func BenchmarkSerializeExtended(b *testing.B) {
	for _, n := range benchInputSizes {
		b.Run(fmt.Sprintf("inputs=%d", n), func(b *testing.B) {
			tx := benchP2PKHTx(b, n)

			b.ReportAllocs()
			for b.Loop() {
				if _, err := tx.EF(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkSize measures Size, which serializes to count bytes.
func BenchmarkSize(b *testing.B) {
	for _, n := range benchInputSizes {
		b.Run(fmt.Sprintf("inputs=%d", n), func(b *testing.B) {
			tx := benchP2PKHTx(b, n)

			b.ReportAllocs()
			for b.Loop() {
				_ = tx.Size()
			}
		})
	}
}

// BenchmarkNewTransactionFromBytes measures raw deserialization.
func BenchmarkNewTransactionFromBytes(b *testing.B) {
	for _, n := range benchInputSizes {
		b.Run(fmt.Sprintf("inputs=%d", n), func(b *testing.B) {
			raw := benchP2PKHTx(b, n).Bytes()

			b.ReportAllocs()
			for b.Loop() {
				if _, err := transaction.NewTransactionFromBytes(raw); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkNewTransactionFromBytesEF measures deserialization of the
// extended-format byte stream, exercising the EF marker detection path.
func BenchmarkNewTransactionFromBytesEF(b *testing.B) {
	for _, n := range benchInputSizes {
		b.Run(fmt.Sprintf("inputs=%d", n), func(b *testing.B) {
			ef, err := benchP2PKHTx(b, n).EF()
			require.NoError(b, err)

			b.ReportAllocs()
			for b.Loop() {
				if _, err := transaction.NewTransactionFromBytes(ef); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkReadFrom measures streaming deserialization via ReadFrom.
func BenchmarkReadFrom(b *testing.B) {
	for _, n := range benchInputSizes {
		b.Run(fmt.Sprintf("inputs=%d", n), func(b *testing.B) {
			raw := benchP2PKHTx(b, n).Bytes()
			r := bytes.NewReader(raw)

			b.ReportAllocs()
			for b.Loop() {
				r.Reset(raw)
				tx := &transaction.Transaction{}
				if _, err := tx.ReadFrom(r); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkTxRoundTrip measures serialize followed by deserialize.
func BenchmarkTxRoundTrip(b *testing.B) {
	for _, n := range benchInputSizes {
		b.Run(fmt.Sprintf("inputs=%d", n), func(b *testing.B) {
			tx := benchP2PKHTx(b, n)

			b.ReportAllocs()
			for b.Loop() {
				parsed, err := transaction.NewTransactionFromBytes(tx.Bytes())
				if err != nil {
					b.Fatal(err)
				}
				_ = parsed
			}
		})
	}
}

// BenchmarkCalcInputPreimage measures the post-fork (BIP143) sighash preimage
// (signaturehash.go:62).
func BenchmarkCalcInputPreimage(b *testing.B) {
	for _, n := range []int{1, 16, 64} {
		b.Run(fmt.Sprintf("inputs=%d", n), func(b *testing.B) {
			tx := benchP2PKHTx(b, n)

			b.ReportAllocs()
			for b.Loop() {
				if _, err := tx.CalcInputPreimage(0, sighash.AllForkID); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkCalcInputPreimageLegacy measures the pre-fork sighash preimage
// (signaturehash.go CalcInputPreimageLegacy), which ShallowClones the
// transaction and, depending on the flag, empties or blanks outputs (None /
// Single) or slices to the single signing input (AnyOneCanPay) before
// serializing. It scales over input count and the mutation flags so the
// serialization is exercised on every branch.
func BenchmarkCalcInputPreimageLegacy(b *testing.B) {
	flags := []struct {
		name string
		f    sighash.Flag
	}{
		{"All", sighash.All},
		{"None", sighash.None},
		{"Single", sighash.Single},
		{"AllAnyOneCanPay", sighash.All | sighash.AnyOneCanPay},
	}
	for _, n := range []int{1, 16, 64} {
		for _, fl := range flags {
			b.Run(fmt.Sprintf("inputs=%d/%s", n, fl.name), func(b *testing.B) {
				tx := benchP2PKHTx(b, n)

				b.ReportAllocs()
				for b.Loop() {
					if _, err := tx.CalcInputPreimageLegacy(0, fl.f); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkSignP2PKH measures signing one input end to end: the P2PKH template
// drives CalcInputSignatureHash and PrivateKey.Sign (template/p2pkh/p2pkh.go:61).
func BenchmarkSignP2PKH(b *testing.B) {
	priv, err := ec.PrivateKeyFromWif(benchWIF)
	require.NoError(b, err)
	unlock, err := p2pkh.Unlock(priv, nil)
	require.NoError(b, err)

	tx := benchP2PKHTx(b, 1)

	b.ReportAllocs()
	for b.Loop() {
		if _, err := unlock.Sign(tx, 0); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGetFee measures summing the current fee across a transaction's
// inputs and outputs (fees.go:69).
func BenchmarkGetFee(b *testing.B) {
	for _, n := range benchInputSizes {
		b.Run(fmt.Sprintf("inputs=%d", n), func(b *testing.B) {
			tx := benchP2PKHTx(b, n)

			b.ReportAllocs()
			for b.Loop() {
				if _, err := tx.GetFee(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkComputeFee measures the SatoshisPerKilobyte fee model
// (fee_model/sats_per_kb.go:14), which sizes the transaction each call.
func BenchmarkComputeFee(b *testing.B) {
	model := &feemodel.SatoshisPerKilobyte{Satoshis: 50}
	for _, n := range benchInputSizes {
		b.Run(fmt.Sprintf("inputs=%d", n), func(b *testing.B) {
			tx := benchP2PKHTx(b, n)

			b.ReportAllocs()
			for b.Loop() {
				if _, err := model.ComputeFee(tx); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkBEEFRoundTrip measures parsing a BEEF and re-serializing it, seeded
// with the small BRC-62 vector and the large multi-tx Issue96 vector.
func BenchmarkBEEFRoundTrip(b *testing.B) {
	seeds := map[string]string{
		"brc62":   BRC62Hex,
		"issue96": testdata.Issue96BeefHex,
	}
	for name, h := range seeds {
		b.Run(name, func(b *testing.B) {
			beef, err := hex.DecodeString(h)
			require.NoError(b, err)

			b.ReportAllocs()
			for b.Loop() {
				tx, err := transaction.NewTransactionFromBEEF(beef)
				if err != nil {
					b.Fatal(err)
				}
				if _, err = tx.BEEF(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkEFRoundTrip measures parsing an extended-format transaction and
// re-serializing it back to EF.
func BenchmarkEFRoundTrip(b *testing.B) {
	tx, err := transaction.NewTransactionFromBEEFHex(BRC62Hex)
	require.NoError(b, err)
	ef, err := tx.EF()
	require.NoError(b, err)

	b.ReportAllocs()
	for b.Loop() {
		parsed, err := transaction.NewTransactionFromBytes(ef)
		if err != nil {
			b.Fatal(err)
		}
		if _, err = parsed.EF(); err != nil {
			b.Fatal(err)
		}
	}
}
