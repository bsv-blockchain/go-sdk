package p2pkh_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

// TestSignWithCacheMatchesSign verifies P2PKH.SignWithCache -- the O(N) signing
// path Transaction.Sign uses for multi-input transactions -- produces scripts
// byte-identical to Sign, both per input and end-to-end through tx.Sign().
func TestSignWithCacheMatchesSign(t *testing.T) {
	priv, err := ec.PrivateKeyFromWif("cNGwGSc7KRrTmdLUZ54fiSXWbhLNDc2Eg5zNucgQxyQCzuQ5YRDq")
	require.NoError(t, err)
	addr, err := script.NewAddressFromPublicKey(priv.PubKey(), true)
	require.NoError(t, err)
	lock, err := p2pkh.Lock(addr)
	require.NoError(t, err)
	unlocker, err := p2pkh.Unlock(priv, nil)
	require.NoError(t, err)

	build := func() *transaction.Transaction {
		tx := transaction.NewTransaction()
		for i := range 3 {
			src := transaction.NewTransaction()
			src.LockTime = uint32(i)
			src.AddOutput(&transaction.TransactionOutput{Satoshis: 100_000, LockingScript: lock})
			tx.AddInputFromTx(src, 0, unlocker)
		}
		tx.AddOutput(&transaction.TransactionOutput{Satoshis: 290_000, LockingScript: lock})
		return tx
	}

	// Reference: sign every input with Sign (no cache).
	ref := build()
	for i := range ref.Inputs {
		s, signErr := unlocker.Sign(ref, uint32(i))
		require.NoError(t, signErr)
		ref.Inputs[i].UnlockingScript = s
	}

	// SignWithCache with a shared cache must match Sign for every input.
	cached := build()
	cache := cached.NewSigHashCache()
	for i := range cached.Inputs {
		s, signErr := unlocker.SignWithCache(cached, uint32(i), cache)
		require.NoError(t, signErr)
		require.Equal(t, *ref.Inputs[i].UnlockingScript, *s, "SignWithCache input %d", i)
		cached.Inputs[i].UnlockingScript = s
	}

	// tx.Sign() dispatches to SignWithCache for p2pkh; the fully signed tx must
	// be byte-identical to the reference signed input-by-input via Sign.
	viaSign := build()
	require.NoError(t, viaSign.Sign())
	require.Equal(t, ref.Bytes(), viaSign.Bytes())
}
