package transaction_test

// Focused regression tests for GHSA-rh54-8fpg-8wwf's digest-selection fix:
// CalcInputSignatureHashWithForkIDEnabled must AND the caller-supplied
// forkIDEnabled with the signature's own ForkID bit when selecting BIP143 vs
// the legacy digest, exactly as node's SignatureHash(..., enabledSighashForkid)
// does, while CalcInputSignatureHash's own (forkIDEnabled=true) behavior stays
// byte-identical to before this fix.

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

func sigNewTestTx(t *testing.T) *transaction.Transaction {
	t.Helper()
	tx, err := transaction.NewTransactionFromHex(sighashTx1In2Out)
	require.NoError(t, err)
	prevScript, err := script.NewFromHex(sighashScriptA)
	require.NoError(t, err)
	out := &transaction.TransactionOutput{LockingScript: prevScript, Satoshis: 100000000}
	tx.Inputs[0].SetSourceTxOutput(out)
	return tx
}

func TestGHSASigCalcInputSignatureHashWithForkIDEnabled(t *testing.T) {
	t.Parallel()

	t.Run("forkIDEnabled=true matches CalcInputSignatureHash's existing (unchanged) behavior", func(t *testing.T) {
		t.Parallel()
		tx := sigNewTestTx(t)
		for _, flag := range []sighash.Flag{sighash.AllForkID, sighash.All, sighash.NoneForkID, sighash.SingleForkID | sighash.AnyOneCanPay} {
			want, err := tx.CalcInputSignatureHash(0, flag)
			require.NoError(t, err)
			got, err := tx.CalcInputSignatureHashWithForkIDEnabled(0, flag, true)
			require.NoError(t, err)
			require.True(t, bytes.Equal(want, got), "flag %v: forkIDEnabled=true must reproduce CalcInputSignatureHash exactly", flag)
		}
	})

	t.Run("forkIDEnabled=false forces the legacy digest even when the sig carries the ForkID bit", func(t *testing.T) {
		t.Parallel()
		tx := sigNewTestTx(t)

		got, err := tx.CalcInputSignatureHashWithForkIDEnabled(0, sighash.AllForkID, false)
		require.NoError(t, err)

		legacyPreimage, err := tx.CalcInputPreimageLegacy(0, sighash.AllForkID)
		require.NoError(t, err)
		want := crypto.Sha256d(legacyPreimage)

		require.True(t, bytes.Equal(want, got), "forkIDEnabled=false must select the legacy/original digest, not BIP143")

		// And it must differ from the BIP143 digest for the same hash type
		// (otherwise this test could not distinguish the two paths).
		bip143, err := tx.CalcInputSignatureHashWithForkIDEnabled(0, sighash.AllForkID, true)
		require.NoError(t, err)
		require.False(t, bytes.Equal(bip143, got), "legacy and BIP143 digests must differ for the same non-empty scriptCode/tx")
	})

	t.Run("forkIDEnabled=true still requires the sig's own ForkID bit (Chronicle forces legacy too)", func(t *testing.T) {
		t.Parallel()
		tx := sigNewTestTx(t)

		// A hash type without ForkID never uses BIP143, engine flag or not.
		got, err := tx.CalcInputSignatureHashWithForkIDEnabled(0, sighash.All, true)
		require.NoError(t, err)
		legacyPreimage, err := tx.CalcInputPreimageLegacy(0, sighash.All)
		require.NoError(t, err)
		require.True(t, bytes.Equal(crypto.Sha256d(legacyPreimage), got))

		// A Chronicle-bit ForkID hash type also forces legacy (the
		// digest-selection side of the SIGHASH_CHRONICLE fix:
		// usesBip143Preimage's own Chronicle check), independent of
		// forkIDEnabled.
		chronicleForkID := sighash.AllForkID | sighash.Chronicle
		got2, err := tx.CalcInputSignatureHashWithForkIDEnabled(0, chronicleForkID, true)
		require.NoError(t, err)
		legacyPreimage2, err := tx.CalcInputPreimageLegacy(0, chronicleForkID)
		require.NoError(t, err)
		require.True(t, bytes.Equal(crypto.Sha256d(legacyPreimage2), got2))
	})
}
