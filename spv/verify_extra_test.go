package spv

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	feemodel "github.com/bsv-blockchain/go-sdk/transaction/fee_model"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

const spvWIF = "KznvCNc6Yf4iztSThoMH6oHWzH9EgjfodKxmeuUGPq5DEX5maspS"

// signedP2PKHTx builds a signed 1-in/1-out P2PKH transaction whose single source
// transaction has no inputs and no merkle path, so Verify completes entirely
// from scripts without ever consulting a chain tracker.
func signedP2PKHTx(t *testing.T) *transaction.Transaction {
	t.Helper()
	priv, err := ec.PrivateKeyFromWif(spvWIF)
	require.NoError(t, err)
	addr, err := script.NewAddressFromPublicKey(priv.PubKey(), true)
	require.NoError(t, err)
	lock, err := p2pkh.Lock(addr)
	require.NoError(t, err)
	unlocker, err := p2pkh.Unlock(priv, nil)
	require.NoError(t, err)

	tx := transaction.NewTransaction()
	src := transaction.NewTransaction()
	src.AddOutput(&transaction.TransactionOutput{Satoshis: 100_000, LockingScript: lock})
	tx.AddInputFromTx(src, 0, unlocker)
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: lock})
	require.NoError(t, tx.Sign())
	return tx
}

// skepticalHeaders is a ChainTracker that rejects every merkle root.
type skepticalHeaders struct{}

func (skepticalHeaders) IsValidRootForHeight(context.Context, *chainhash.Hash, uint32) (bool, error) {
	return false, nil
}
func (skepticalHeaders) CurrentHeight(context.Context) (uint32, error) { return 0, nil }

// erroringHeaders is a ChainTracker whose lookups always fail.
type erroringHeaders struct{}

func (erroringHeaders) IsValidRootForHeight(context.Context, *chainhash.Hash, uint32) (bool, error) {
	return false, errors.New("header service unavailable")
}
func (erroringHeaders) CurrentHeight(context.Context) (uint32, error) { return 0, nil }

// TestSPVVerifyNilChainTrackerNoMerklePath covers the nil-chainTracker default:
// a fully-scripted transaction with no merkle path anywhere verifies without the
// tracker ever being used (so no network).
func TestSPVVerifyNilChainTrackerNoMerklePath(t *testing.T) {
	tx := signedP2PKHTx(t)
	verified, err := Verify(t.Context(), tx, nil, nil)
	require.NoError(t, err)
	require.True(t, verified)
}

// TestSPVVerifyMissingSourceOutput covers the missing-source-output branch.
func TestSPVVerifyMissingSourceOutput(t *testing.T) {
	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       &chainhash.Hash{},
		SourceTxOutIndex: 0,
		SequenceNumber:   transaction.DefaultSequenceNumber,
	})
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1, LockingScript: &script.Script{}})

	verified, err := Verify(t.Context(), tx, &GullibleHeadersClient{}, nil)
	require.ErrorIs(t, err, ErrMissingSourceTransaction)
	require.False(t, verified)
}

// TestSPVVerifyScriptFailure covers the script-verification-failure branch: a
// valid source output spent by an empty (invalid) unlocking script.
func TestSPVVerifyScriptFailure(t *testing.T) {
	priv, err := ec.PrivateKeyFromWif(spvWIF)
	require.NoError(t, err)
	addr, err := script.NewAddressFromPublicKey(priv.PubKey(), true)
	require.NoError(t, err)
	lock, err := p2pkh.Lock(addr)
	require.NoError(t, err)

	tx := transaction.NewTransaction()
	src := transaction.NewTransaction()
	src.AddOutput(&transaction.TransactionOutput{Satoshis: 100_000, LockingScript: lock})
	tx.AddInputFromTx(src, 0, nil)
	tx.Inputs[0].UnlockingScript = &script.Script{} // never satisfies the P2PKH lock
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: lock})

	verified, err := Verify(t.Context(), tx, &GullibleHeadersClient{}, nil)
	require.ErrorIs(t, err, ErrScriptVerificationFailed)
	require.False(t, verified)
}

// TestSPVVerifyInvalidMerklePath covers the branch where the chain tracker
// rejects the merkle root.
func TestSPVVerifyInvalidMerklePath(t *testing.T) {
	tx, err := transaction.NewTransactionFromBEEFHex(BRC62Hex)
	require.NoError(t, err)

	verified, err := Verify(t.Context(), tx, skepticalHeaders{}, nil)
	require.ErrorIs(t, err, ErrInvalidMerklePath)
	require.False(t, verified)
}

// TestSPVVerifyMerklePathLookupError covers the branch where the chain tracker
// lookup itself errors.
func TestSPVVerifyMerklePathLookupError(t *testing.T) {
	tx, err := transaction.NewTransactionFromBEEFHex(BRC62Hex)
	require.NoError(t, err)

	verified, err := Verify(t.Context(), tx, erroringHeaders{}, nil)
	require.Error(t, err)
	require.False(t, verified)
}

// TestSPVVerifyFeeErrorWithMissingSource covers the GetFee error branch reached
// when fee validation is requested but an input has no source satoshis.
func TestSPVVerifyFeeErrorWithMissingSource(t *testing.T) {
	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       &chainhash.Hash{},
		SourceTxOutIndex: 0,
		SequenceNumber:   transaction.DefaultSequenceNumber,
	})
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1, LockingScript: &script.Script{}})

	verified, err := Verify(t.Context(), tx, &GullibleHeadersClient{}, &feemodel.SatoshisPerKilobyte{Satoshis: 1})
	require.Error(t, err)
	require.False(t, verified)
}

// TestSPVVerifyChronicleOpcodes covers script verification under Chronicle
// rules: an input whose locking script uses a Chronicle re-enabled opcode
// (OP_2MUL) must verify, as it does on the network.
func TestSPVVerifyChronicleOpcodes(t *testing.T) {
	// OP_2 OP_2MUL OP_4 OP_EQUAL → 2*2 == 4 → true, with an empty unlocking script.
	lock := &script.Script{}
	require.NoError(t, lock.AppendOpcodes(script.Op2, script.Op2MUL, script.Op4, script.OpEQUAL))

	tx := transaction.NewTransaction()
	src := transaction.NewTransaction()
	src.AddOutput(&transaction.TransactionOutput{Satoshis: 100_000, LockingScript: lock})
	tx.AddInputFromTx(src, 0, nil)
	tx.Inputs[0].UnlockingScript = &script.Script{}
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: lock})

	verified, err := Verify(t.Context(), tx, &GullibleHeadersClient{}, nil)
	require.NoError(t, err)
	require.True(t, verified)
}
