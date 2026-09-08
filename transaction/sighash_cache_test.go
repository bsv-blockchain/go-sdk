package transaction_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/script"
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
			benchAllPreimages(b, tx, nIn, false)
		})
		b.Run(fmt.Sprintf("cached/inputs=%d", nIn), func(b *testing.B) {
			benchAllPreimages(b, tx, nIn, true)
		})
	}
}

// benchAllPreimages computes the sighash preimage for every input of tx once per
// b.Loop iteration. With useCache the BIP143 midstates are computed once per pass
// (O(N)); without it each call recomputes them (O(N^2)). A nil cache to
// CalcInputPreimageWithCache is exactly CalcInputPreimage.
func benchAllPreimages(b *testing.B, tx *transaction.Transaction, nIn int, useCache bool) {
	b.Helper()
	b.ReportAllocs()
	for b.Loop() {
		var cache *transaction.SigHashCache
		if useCache {
			cache = tx.NewSigHashCache()
		}
		for vin := range nIn {
			if _, err := tx.CalcInputPreimageWithCache(uint32(vin), sighash.AllForkID, cache); err != nil {
				b.Fatal(err)
			}
		}
	}
}

// noCacheTemplate implements only UnlockingScriptTemplate (no SignWithCache), to
// exercise Transaction.Sign's backward-compatible fallback for external
// templates that predate the cache interface.
type noCacheTemplate struct{ signs *int }

func (n noCacheTemplate) Sign(_ *transaction.Transaction, _ uint32) (*script.Script, error) {
	*n.signs++
	return &script.Script{}, nil
}

func (n noCacheTemplate) EstimateLength(_ *transaction.Transaction, _ uint32) uint32 { return 0 }

// TestSignFallsBackForNonCacheTemplate verifies Transaction.Sign still drives a
// template that does not implement UnlockingScriptTemplateWithCache.
func TestSignFallsBackForNonCacheTemplate(t *testing.T) {
	var signs int
	tx := transaction.NewTransaction()
	for i := range 3 {
		src := transaction.NewTransaction()
		src.LockTime = uint32(i)
		src.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: &script.Script{}})
		tx.AddInputFromTx(src, 0, noCacheTemplate{signs: &signs})
	}
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 2000, LockingScript: &script.Script{}})

	require.NoError(t, tx.Sign())
	require.Equal(t, 3, signs, "each input signed via the fallback Sign path")
	for i, in := range tx.Inputs {
		require.NotNil(t, in.UnlockingScript, "input %d unlocking script set", i)
	}
}

// TestCalcInputSignatureHashWithCacheLegacyFallback verifies the cached API
// falls back to the legacy (pre-fork) algorithm for non-FORKID flags,
// byte-identically to CalcInputSignatureHash.
func TestCalcInputSignatureHashWithCacheLegacyFallback(t *testing.T) {
	tx := benchP2PKHTx(t, 2)
	cache := tx.NewSigHashCache()
	for _, f := range []sighash.Flag{sighash.All, sighash.None, sighash.Single} {
		for vin := range 2 {
			want, err := tx.CalcInputSignatureHash(uint32(vin), f)
			require.NoError(t, err)
			got, err := tx.CalcInputSignatureHashWithCache(uint32(vin), f, cache)
			require.NoError(t, err)
			require.Equal(t, want, got, "legacy flag=%v input=%d", f, vin)
		}
	}
}
