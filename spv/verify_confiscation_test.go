package spv

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// confiscationOrder returns an output 0 script in the confiscation protocol's
// layout (frozentxo_db.cpp:648-655): the marker, version 1 and a 20-byte
// confiscation order hash.
func confiscationOrder() *script.Script {
	b := append([]byte{}, confiscationMarker...)
	b = append(b, 0x01, 0x01, 0x14)
	b = append(b, make([]byte, 20)...)
	return script.NewFromBytes(b)
}

// spendWithOutputs returns an unmined transaction spending output vout of src
// with an empty unlocking script and paying outs.
func spendWithOutputs(src *transaction.Transaction, vout uint32, outs ...*transaction.TransactionOutput) *transaction.Transaction {
	tx := transaction.NewTransaction()
	tx.AddInputFromTx(src, vout, nil)
	tx.Inputs[0].UnlockingScript = &script.Script{}
	for _, out := range outs {
		tx.AddOutput(out)
	}
	return tx
}

// TestSPVVerifyUnminedConfiscationTx checks that an unmined transaction whose
// output 0 starts with the confiscation marker is rejected. A node only
// accepts one that is whitelisted (Consensus::CheckTxInputs,
// validation.cpp:2563-2587), and Verify cannot see the whitelist.
func TestSPVVerifyUnminedConfiscationTx(t *testing.T) {
	const tip = 700_000
	src := minedSource(t, opTrue, 600_000)

	for name, lock := range map[string]*script.Script{
		"order":       confiscationOrder(),
		"bare marker": script.NewFromBytes(confiscationMarker),
	} {
		t.Run(name, func(t *testing.T) {
			tx := spendWithOutputs(src, 0,
				&transaction.TransactionOutput{Satoshis: 0, LockingScript: lock},
				&transaction.TransactionOutput{Satoshis: 1000, LockingScript: opTrue},
			)
			verified, err := Verify(t.Context(), tx, tipTracker(tip), nil)
			require.ErrorIs(t, err, ErrConfiscationTransaction)
			require.False(t, verified)

			// No chain tip is needed to recognise one.
			verified, err = VerifyScripts(t.Context(), tx)
			require.ErrorIs(t, err, ErrConfiscationTransaction)
			require.False(t, verified)
		})
	}
}

// TestSPVVerifyNotConfiscationTx checks transactions IsConfiscationTx does not
// match: a marker one byte short, and the full marker in an output other
// than output 0.
func TestSPVVerifyNotConfiscationTx(t *testing.T) {
	const tip = 700_000
	src := minedSource(t, opTrue, 600_000)

	short := spendWithOutputs(src, 0,
		&transaction.TransactionOutput{Satoshis: 0, LockingScript: script.NewFromBytes(confiscationMarker[:6])},
		&transaction.TransactionOutput{Satoshis: 1000, LockingScript: opTrue},
	)
	verified, err := Verify(t.Context(), short, tipTracker(tip), nil)
	require.NoError(t, err)
	require.True(t, verified)

	second := spendWithOutputs(src, 0,
		&transaction.TransactionOutput{Satoshis: 1000, LockingScript: opTrue},
		&transaction.TransactionOutput{Satoshis: 0, LockingScript: confiscationOrder()},
	)
	verified, err = Verify(t.Context(), second, tipTracker(tip), nil)
	require.NoError(t, err)
	require.True(t, verified)
}

// confiscationSource returns a confiscation transaction mined at height,
// whose output 1 pays opTrue.
func confiscationSource(t *testing.T, height uint32) *transaction.Transaction {
	t.Helper()
	src := transaction.NewTransaction()
	src.AddOutput(&transaction.TransactionOutput{Satoshis: 0, LockingScript: confiscationOrder()})
	src.AddOutput(&transaction.TransactionOutput{Satoshis: 100_000, LockingScript: opTrue})
	mp, err := transaction.NewMerklePathFromCoinbaseTxid(src.TxID(), height)
	require.NoError(t, err)
	src.MerklePath = mp
	return src
}

// TestSPVVerifyConfiscationMaturity checks Consensus::CheckTxInputs' rule
// that a confiscation transaction's outputs cannot be spent until they are
// CONFISCATION_MATURITY (1000) blocks deep (validation.cpp:2628-2636).
func TestSPVVerifyConfiscationMaturity(t *testing.T) {
	const tip = 700_000
	pay := &transaction.TransactionOutput{Satoshis: 1000, LockingScript: opTrue}

	// One block short.
	tx := spendWithOutputs(confiscationSource(t, tip-confiscationMaturity+2), 1, pay)
	verified, err := Verify(t.Context(), tx, tipTracker(tip), nil)
	require.ErrorIs(t, err, ErrPrematureConfiscationSpend)
	require.False(t, verified)

	// Exactly confiscationMaturity blocks deep.
	tx = spendWithOutputs(confiscationSource(t, tip-confiscationMaturity+1), 1, pay)
	verified, err = Verify(t.Context(), tx, tipTracker(tip), nil)
	require.NoError(t, err)
	require.True(t, verified)

	// VerifyScripts has no chain tip and skips maturity, as it does for a
	// coinbase.
	tx = spendWithOutputs(confiscationSource(t, tip), 1, pay)
	verified, err = VerifyScripts(t.Context(), tx)
	require.NoError(t, err)
	require.True(t, verified)
}

// TestSPVVerifyCoinbaseConfiscationMaturity checks that a mined coinbase
// whose output 0 carries the confiscation marker has confiscation outputs,
// as UpdateCoins marks every transaction's outputs by IsConfiscationTx
// (validation.cpp:2495), so the longer confiscation maturity applies.
func TestSPVVerifyCoinbaseConfiscationMaturity(t *testing.T) {
	const tip = 700_000
	height := uint32(tip - coinbaseMaturity - 10)
	cb := coinbaseSource(t, opTrue, height)
	cb.Outputs = []*transaction.TransactionOutput{
		{Satoshis: 0, LockingScript: confiscationOrder()},
		{Satoshis: 100_000, LockingScript: opTrue},
	}
	mp, err := transaction.NewMerklePathFromCoinbaseTxid(cb.TxID(), height)
	require.NoError(t, err)
	cb.MerklePath = mp

	tx := spendWithOutputs(cb, 1, &transaction.TransactionOutput{Satoshis: 1000, LockingScript: opTrue})
	verified, err := Verify(t.Context(), tx, tipTracker(tip), nil)
	require.ErrorIs(t, err, ErrPrematureConfiscationSpend)
	require.False(t, verified)
}
