package spv

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// buildCopySubstitutionX returns two Transaction values, each with X's txid:
// value A carries X's real source (a P2PKH output priv locks), which X's
// (always empty) unlocking script does not satisfy; value B instead carries
// SetSourceTxOutput(opTrue) for the same input, which any unlocking script
// satisfies. X's own inputs and outputs are otherwise identical between A
// and B, so they share a txid despite carrying different evidence for what
// their one input spends.
func buildCopySubstitutionX(t *testing.T) (a, b *transaction.Transaction) {
	t.Helper()
	_, lock := spvKey(t)
	realSrc := minedSource(t, lock, 100)

	build := func() *transaction.Transaction {
		x := transaction.NewTransaction()
		x.AddInputFromTx(realSrc, 0, nil)
		x.Inputs[0].UnlockingScript = &script.Script{} // never satisfies the P2PKH lock
		x.AddOutput(&transaction.TransactionOutput{Satoshis: 100, LockingScript: opTrue})
		x.AddOutput(&transaction.TransactionOutput{Satoshis: 100, LockingScript: opTrue})
		return x
	}
	a = build()
	b = build()
	require.True(t, a.TxID().IsEqual(b.TxID()), "a and b must share a txid for this scenario")

	b.Inputs[0].SourceTransaction = nil
	b.Inputs[0].SetSourceTxOutput(&transaction.TransactionOutput{Satoshis: realSrc.Outputs[0].Satoshis, LockingScript: opTrue})
	return a, b
}

// TestSPVVerifyCopySubstitutionAcrossInputs checks that two Transaction
// values of one unmined transaction X, reached through two inputs of a
// child, are each verified by their own evidence, so that a copy carrying a
// trusted output cannot stand in for one carrying X's real source.
func TestSPVVerifyCopySubstitutionAcrossInputs(t *testing.T) {
	for _, name := range []string{"real-source copy first", "trusted-output copy first"} {
		a, b := buildCopySubstitutionX(t)
		first, second := a, b
		if name == "trusted-output copy first" {
			first, second = b, a
		}

		child := transaction.NewTransaction()
		child.AddInputFromTx(first, 0, nil)
		child.Inputs[0].UnlockingScript = &script.Script{}
		child.AddInputFromTx(second, 1, nil)
		child.Inputs[1].UnlockingScript = &script.Script{}
		child.AddOutput(&transaction.TransactionOutput{Satoshis: 150, LockingScript: opTrue})

		verified, err := Verify(t.Context(), child, &GullibleHeadersClient{}, nil)
		require.ErrorIs(t, err, ErrScriptVerificationFailed, name)
		require.False(t, verified, name)
	}
}

// TestEvidenceOfDistinguishesInputClaims is a whitebox check that evidenceOf
// gives a different fingerprint to a "carries its source transaction"
// input than to a "carries a directly supplied output" input, even when the
// supplied output's amount and locking script match the source's, and the
// same fingerprint to two source-carrying inputs regardless of which
// Transaction value they point to (proveMined already ties any such value
// to the input's fixed SourceTXID).
func TestEvidenceOfDistinguishesInputClaims(t *testing.T) {
	realSrc := minedCoins(t, 100)

	withSource := transaction.NewTransaction()
	withSource.AddInputFromTx(realSrc, 0, nil)

	otherPointer := transaction.NewTransaction()
	otherPointer.AddInputFromTx(realSrc, 0, nil)
	// A different (but equal-content) source pointer still counts as
	// "carries its source transaction".
	otherPointer.Inputs[0].SourceTransaction = copyOf(t, realSrc, realSrc.MerklePath)

	withOutput := transaction.NewTransaction()
	in := &transaction.TransactionInput{SourceTXID: realSrc.TxID(), SequenceNumber: transaction.DefaultSequenceNumber}
	in.SetSourceTxOutput(&transaction.TransactionOutput{Satoshis: realSrc.Outputs[0].Satoshis, LockingScript: realSrc.Outputs[0].LockingScript})
	withOutput.AddInput(in)

	missing := transaction.NewTransaction()
	missing.AddInput(&transaction.TransactionInput{SourceTXID: realSrc.TxID(), SequenceNumber: transaction.DefaultSequenceNumber})

	g := &txGraph{}
	require.Equal(t, g.evidenceOf(withSource), g.evidenceOf(otherPointer))
	require.NotEqual(t, g.evidenceOf(withSource), g.evidenceOf(withOutput))
	require.NotEqual(t, g.evidenceOf(withSource), g.evidenceOf(missing))
	require.NotEqual(t, g.evidenceOf(withOutput), g.evidenceOf(missing))
}

// TestEvidenceOfCachesOutputFingerprint checks that evidenceOf hashes a
// SetSourceTxOutput output once per Verify call however many Transaction
// values share it: outputFingerprint caches the digest per
// *TransactionOutput.
func TestEvidenceOfCachesOutputFingerprint(t *testing.T) {
	out := &transaction.TransactionOutput{Satoshis: 1000, LockingScript: opTrue}

	// Two pointer-distinct Transaction values, each with its own input, but
	// both inputs point at the very same *TransactionOutput.
	a := transaction.NewTransaction()
	a.AddInput(&transaction.TransactionInput{SourceTXID: &chainhash.Hash{}, SequenceNumber: transaction.DefaultSequenceNumber})
	a.Inputs[0].SetSourceTxOutput(out)
	b := transaction.NewTransaction()
	b.AddInput(&transaction.TransactionInput{SourceTXID: &chainhash.Hash{}, SequenceNumber: transaction.DefaultSequenceNumber})
	b.Inputs[0].SetSourceTxOutput(out)

	g := &txGraph{}
	fpA := g.evidenceOf(a)
	fpB := g.evidenceOf(b)
	require.Equal(t, fpA, fpB, "the same output must fingerprint the same regardless of which Transaction value reached it")
	require.Len(t, g.outputFingerprints, 1, "outputFingerprint must cache by pointer rather than hash the shared output again for b")
}
