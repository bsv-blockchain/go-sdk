package interpreter

import (
	"testing"

	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/errs"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

// TestExecuteWithoutFlagOptions checks that Execute with no flag option
// enables SIGHASH_FORKID, so an ordinary SIGHASH_ALL|FORKID P2PKH spend
// verifies as it did before, while WithFlags(0) keeps node's semantics for an
// empty flag word, which checks such a signature against the original digest.
func TestExecuteWithoutFlagOptions(t *testing.T) {
	t.Parallel()

	priv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	addr, err := script.NewAddressFromPublicKey(priv.PubKey(), true)
	require.NoError(t, err)
	lock, err := p2pkh.Lock(addr)
	require.NoError(t, err)
	unlocker, err := p2pkh.Unlock(priv, nil)
	require.NoError(t, err)

	src := transaction.NewTransaction()
	src.AddOutput(&transaction.TransactionOutput{Satoshis: 10_000, LockingScript: lock})
	tx := transaction.NewTransaction()
	tx.AddInputFromTx(src, 0, unlocker)
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 9_000, LockingScript: lock})
	require.NoError(t, tx.Sign())
	prev := src.Outputs[0]

	require.NoError(t, NewEngine().Execute(WithTx(tx, 0, prev)))
	require.NoError(t, NewEngine().Execute(WithTx(tx, 0, prev), WithAfterGenesis()))

	err = NewEngine().Execute(WithTx(tx, 0, prev), WithFlags(0))
	require.True(t, errs.IsErrorCode(err, errs.ErrEvalFalse), "%v", err)
}
