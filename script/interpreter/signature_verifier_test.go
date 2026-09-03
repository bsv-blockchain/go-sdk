package interpreter_test

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/stretchr/testify/require"
)

func TestInjectExternalVerifySignatureFn(t *testing.T) {
	t.Cleanup(func() { interpreter.InjectExternalVerifySignatureFn(nil) })

	const signedTx = "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d2507232651000000006b483045022100c1d77036dc6cd1f3fa1214b0688391ab7f7a16cd31ea4e5a1f7a415ef167df820220751aced6d24649fa235132f1e6969e163b9400f80043a72879237dab4a1190ad412103b8b40a84123121d260f5c109bc5a46ec819c2e4002e5ba08638783bfb4e01435ffffffff02404b4c00000000001976a91404ff367be719efa79d76e4416ffb072cd53b208888acde94a905000000001976a91404d03f746652cfcb6cb55119ab473a045137d26588ac00000000"
	tx, err := transaction.NewTransactionFromHex(signedTx)
	require.NoError(t, err)

	lockingScript, err := script.NewFromHex("76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac")
	require.NoError(t, err)
	previousOutput := &transaction.TransactionOutput{
		Satoshis:      100000000,
		LockingScript: lockingScript,
	}
	tx.Inputs[0].SetSourceTxOutput(previousOutput)

	callCount := 0
	interpreter.InjectExternalVerifySignatureFn(func(payload, signature, publicKey []byte) bool {
		callCount++
		require.Len(t, payload, 32)
		require.NotEmpty(t, signature)
		require.Contains(t, []int{33, 65}, len(publicKey))
		return true
	})

	err = interpreter.NewEngine().Execute(
		interpreter.WithTx(tx, 0, previousOutput),
		interpreter.WithForkID(),
		interpreter.WithAfterGenesis(),
	)
	require.NoError(t, err)
	require.Equal(t, 1, callCount)

	interpreter.InjectExternalVerifySignatureFn(nil)
	err = interpreter.NewEngine().Execute(
		interpreter.WithTx(tx, 0, previousOutput),
		interpreter.WithForkID(),
		interpreter.WithAfterGenesis(),
	)
	require.NoError(t, err)
}
