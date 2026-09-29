package spv

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// efP2SHSpend returns an Extended-Format-style transaction: one input with
// no SourceTransaction, spending a P2SH-shaped output supplied with
// SetSourceTxOutput, whose redeem script is <pubkey> OP_CHECKSIG. Nothing
// proves this coin's height, or even that it exists.
func efP2SHSpend(t *testing.T, signed bool) *transaction.Transaction {
	t.Helper()
	priv, lock := spvKey(t)
	redeem := p2shRedeem(t, priv)
	srcTxid := chainhash.DoubleHashH([]byte("spv EF P2SH source"))

	in := &transaction.TransactionInput{
		SourceTXID:      &srcTxid,
		SequenceNumber:  transaction.DefaultSequenceNumber,
		UnlockingScript: &script.Script{},
	}
	tx := transaction.NewTransaction()
	tx.AddInput(in)
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: lock})

	unlock := &script.Script{}
	if signed {
		// The signature is over the redeem script as scriptCode, standing
		// in as the spent output's locking script, as unlockP2SH does for
		// an input that carries its source transaction.
		in.SetSourceTxOutput(&transaction.TransactionOutput{Satoshis: 50_000, LockingScript: redeem})
		digest, err := tx.CalcInputSignatureHash(0, sighash.AllForkID)
		require.NoError(t, err)
		sig, err := priv.Sign(digest)
		require.NoError(t, err)
		require.NoError(t, unlock.AppendPushData(append(sig.Serialize(), byte(sighash.AllForkID))))
	}
	in.SetSourceTxOutput(&transaction.TransactionOutput{Satoshis: 50_000, LockingScript: p2shOf(*redeem)})
	require.NoError(t, unlock.AppendPushData(*redeem))
	in.UnlockingScript = unlock
	return tx
}

// TestSPVVerifyEFInputP2SHForcedPreGenesis checks that an Extended Format
// input spending a P2SH-shaped output must satisfy its redeem script: with
// no source transaction at all, coinHeight defaults to unminedHeight, which
// p2shCoinHeight forces pre-Genesis, so the redeem script alone (with no
// signature) does not satisfy it.
func TestSPVVerifyEFInputP2SHForcedPreGenesis(t *testing.T) {
	verified, err := Verify(t.Context(), efP2SHSpend(t, false), &GullibleHeadersClient{}, nil)
	require.ErrorIs(t, err, ErrScriptVerificationFailed)
	require.False(t, verified)

	verified, err = Verify(t.Context(), efP2SHSpend(t, true), &GullibleHeadersClient{}, nil)
	require.NoError(t, err)
	require.True(t, verified)
}

// TestSPVVerifyScriptsP2SHForgedHeight checks that VerifyScripts, which
// trusts every merkle path GullibleHeadersClient is asked to confirm, still
// forces a P2SH-shaped output to a pre-Genesis era when its source is not a
// proven-mined coinbase: a merkle path claiming height 700,000 (post-Genesis
// on mainnet) does not let the redeem script be skipped, since a real chain
// could never have such a merkle path for a non-coinbase source.
func TestSPVVerifyScriptsP2SHForgedHeight(t *testing.T) {
	unsigned := p2shSpend(t, 700_000, false)
	verified, err := VerifyScripts(t.Context(), unsigned)
	require.ErrorIs(t, err, ErrScriptVerificationFailed)
	require.False(t, verified)

	signed := p2shSpend(t, 700_000, true)
	verified, err = VerifyScripts(t.Context(), signed)
	require.NoError(t, err)
	require.True(t, verified)
}

// TestP2SHCoinHeight is a whitebox test of p2shCoinHeight's clamp.
func TestP2SHCoinHeight(t *testing.T) {
	g := &txGraph{heights: map[chainhash.Hash]uint32{}}
	mainnet := scriptflag.MainNetActivationHeights
	p2shOut := &transaction.TransactionOutput{LockingScript: p2shOf([]byte{0x51})}
	nonP2SHOut := &transaction.TransactionOutput{LockingScript: opTrue}
	noSourceInput := &transaction.TransactionInput{}

	// A non-P2SH-shaped output is never clamped.
	require.Equal(t, uint32(999_999_999), g.p2shCoinHeight(noSourceInput, nonP2SHOut, 999_999_999, mainnet))
	// An output with no locking script at all is never clamped.
	require.Equal(t, uint32(999_999_999), g.p2shCoinHeight(noSourceInput, &transaction.TransactionOutput{}, 999_999_999, mainnet))

	// An EF input (no SourceTransaction), or any other source not proven a
	// mined coinbase, spending a P2SH-shaped output is forced to
	// heights.Genesis-1.
	require.Equal(t, mainnet.Genesis-1, g.p2shCoinHeight(noSourceInput, p2shOut, unminedHeight, mainnet))
	require.Equal(t, mainnet.Genesis-1, g.p2shCoinHeight(noSourceInput, p2shOut, mainnet.Genesis, mainnet))

	// A coinHeight already pre-Genesis is left unchanged.
	require.Equal(t, uint32(100), g.p2shCoinHeight(noSourceInput, p2shOut, 100, mainnet))

	// The zero ActivationHeights has no pre-Genesis era: no clamp.
	require.Equal(t, uint32(700_000), g.p2shCoinHeight(noSourceInput, p2shOut, 700_000, scriptflag.ActivationHeights{}))

	// A source that is present but not a coinbase (node-exact test) is
	// still clamped, even proven mined at a post-Genesis height.
	regularSrc := &transaction.Transaction{Inputs: []*transaction.TransactionInput{{SourceTXID: &chainhash.Hash{1}}}}
	srcTxid := chainhash.Hash{2}
	g.heights[srcTxid] = 700_000
	sourcedInput := &transaction.TransactionInput{SourceTXID: &srcTxid, SourceTransaction: regularSrc}
	require.Equal(t, mainnet.Genesis-1, g.p2shCoinHeight(sourcedInput, p2shOut, 700_000, mainnet))

	// A coinbase source proven mined at a post-Genesis height keeps it.
	coinbaseSrc := &transaction.Transaction{Inputs: []*transaction.TransactionInput{{
		SourceTXID:       &chainhash.Hash{},
		SourceTxOutIndex: transaction.DefaultSequenceNumber,
	}}}
	cbTxid := chainhash.Hash{3}
	g.heights[cbTxid] = 700_000
	cbInput := &transaction.TransactionInput{SourceTXID: &cbTxid, SourceTransaction: coinbaseSrc}
	require.Equal(t, uint32(700_000), g.p2shCoinHeight(cbInput, p2shOut, 700_000, mainnet))

	// A coinbase source that is not proven mined is still clamped: only a
	// verified merkle path can prove a coin's height.
	unprovenCbInput := &transaction.TransactionInput{SourceTXID: &chainhash.Hash{4}, SourceTransaction: coinbaseSrc}
	require.Equal(t, mainnet.Genesis-1, g.p2shCoinHeight(unprovenCbInput, p2shOut, unminedHeight, mainnet))
}
