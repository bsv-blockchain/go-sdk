package transaction_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

// P2PKH must satisfy the optional cache interface so Transaction.Sign uses the
// O(N) path for the built-in template.
var _ transaction.UnlockingScriptTemplateWithCache = (*p2pkh.P2PKH)(nil)

var cacheTestFlags = []sighash.Flag{
	sighash.AllForkID,
	sighash.NoneForkID,
	sighash.SingleForkID,
	sighash.AllForkID | sighash.AnyOneCanPay,
	sighash.NoneForkID | sighash.AnyOneCanPay,
	sighash.SingleForkID | sighash.AnyOneCanPay,
}

// TestSigHashCacheEquivalence locks the invariant that the cached preimage and
// signature-hash paths are byte-identical to the uncached ones for every SIGHASH
// flag and input, including when a nil cache is passed.
func TestSigHashCacheEquivalence(t *testing.T) {
	for _, nIn := range []int{1, 3, 8} {
		tx := benchP2PKHTx(t, nIn)
		cache := tx.NewSigHashCache()
		for _, f := range cacheTestFlags {
			for vin := range nIn {
				idx := uint32(vin)

				want, err := tx.CalcInputPreimage(idx, f)
				require.NoError(t, err)

				got, err := tx.CalcInputPreimageWithCache(idx, f, cache)
				require.NoError(t, err)
				require.Equal(t, want, got, "preimage nIn=%d flag=%v input=%d", nIn, f, vin)

				gotNil, err := tx.CalcInputPreimageWithCache(idx, f, nil)
				require.NoError(t, err)
				require.Equal(t, want, gotNil, "preimage nil-cache nIn=%d flag=%v input=%d", nIn, f, vin)

				wantH, err := tx.CalcInputSignatureHash(idx, f)
				require.NoError(t, err)

				gotH, err := tx.CalcInputSignatureHashWithCache(idx, f, cache)
				require.NoError(t, err)
				require.Equal(t, wantH, gotH, "sighash nIn=%d flag=%v input=%d", nIn, f, vin)
			}
		}
	}
}

// BenchmarkPreimageAllInputs contrasts computing the sighash preimage for every
// input of a transaction with and without a shared SigHashCache. Uncached grows
// ~O(N^2) (each call re-hashes all prevouts/sequences/outputs); cached grows
// ~O(N) (midstates computed once per signing pass).
func BenchmarkPreimageAllInputs(b *testing.B) {
	for _, nIn := range []int{1, 16, 64} {
		tx := benchP2PKHTx(b, nIn)

		b.Run(fmt.Sprintf("uncached/inputs=%d", nIn), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				for vin := range nIn {
					if _, err := tx.CalcInputPreimage(uint32(vin), sighash.AllForkID); err != nil {
						b.Fatal(err)
					}
				}
			}
		})

		b.Run(fmt.Sprintf("cached/inputs=%d", nIn), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				cache := tx.NewSigHashCache()
				for vin := range nIn {
					if _, err := tx.CalcInputPreimageWithCache(uint32(vin), sighash.AllForkID, cache); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
