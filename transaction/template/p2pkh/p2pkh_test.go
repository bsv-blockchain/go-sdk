package p2pkh_test

import (
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	script "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/stretchr/testify/require"
)

func TestLocalUnlocker_UnlockAllInputs(t *testing.T) {
	t.Parallel()

	incompleteTx := "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d25072326510000000000ffffffff02404b4c00000000001976a91404ff367be719efa79d76e4416ffb072cd53b208888acde94a905000000001976a91404d03f746652cfcb6cb55119ab473a045137d26588ac00000000"
	tx, err := transaction.NewTransactionFromHex(incompleteTx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	prevTx := transaction.NewTransaction()
	prevTx.Outputs = make([]*transaction.TransactionOutput, tx.InputIdx(0).SourceTxOutIndex+1)
	prevTx.Outputs[tx.InputIdx(0).SourceTxOutIndex] = &transaction.TransactionOutput{Satoshis: 100000000}
	prevTx.Outputs[tx.InputIdx(0).SourceTxOutIndex].LockingScript, err = script.NewFromHex("76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac")
	require.NoError(t, err)
	tx.Inputs[0].SourceTransaction = prevTx

	// Our private key
	priv, err := ec.PrivateKeyFromWif("cNGwGSc7KRrTmdLUZ54fiSXWbhLNDc2Eg5zNucgQxyQCzuQ5YRDq")
	require.NoError(t, err)

	unlocker, err := p2pkh.Unlock(priv, nil)
	require.NoError(t, err)

	s, err := unlocker.Sign(tx, 0)
	require.NoError(t, err)
	tx.Inputs[0].UnlockingScript = s

	expectedSignedTx := "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d2507232651000000006b483045022100c1d77036dc6cd1f3fa1214b0688391ab7f7a16cd31ea4e5a1f7a415ef167df820220751aced6d24649fa235132f1e6969e163b9400f80043a72879237dab4a1190ad412103b8b40a84123121d260f5c109bc5a46ec819c2e4002e5ba08638783bfb4e01435ffffffff02404b4c00000000001976a91404ff367be719efa79d76e4416ffb072cd53b208888acde94a905000000001976a91404d03f746652cfcb6cb55119ab473a045137d26588ac00000000"
	require.Equal(t, expectedSignedTx, tx.String())
	require.NotEqual(t, incompleteTx, tx.String())
}

func TestLocalUnlocker_ValidSignature(t *testing.T) {
	tests := map[string]struct {
		tx *transaction.Transaction
	}{
		"valid signature 1": {
			tx: func() *transaction.Transaction {
				tx := transaction.NewTransaction()
				require.NoError(t, tx.AddInputFrom("45be95d2f2c64e99518ffbbce03fb15a7758f20ee5eecf0df07938d977add71d", 0, "76a914c7c6987b6e2345a6b138e3384141520a0fbc18c588ac", 15564838601, nil))

				script1, err := script.NewFromHex("76a91442f9682260509ac80722b1963aec8a896593d16688ac")
				require.NoError(t, err)

				tx.AddOutput(&transaction.TransactionOutput{
					Satoshis:      375041432,
					LockingScript: script1,
				})

				script2, _ := script.NewFromHex("76a914c36538e91213a8100dcb2aed456ade363de8483f88ac")
				tx.AddOutput(&transaction.TransactionOutput{
					Satoshis:      15189796941,
					LockingScript: script2,
				})

				return tx
			}(),
		},
		"valid signature 2": {
			tx: func() *transaction.Transaction {
				tx := transaction.NewTransaction()

				require.NoError(
					t,
					tx.AddInputFrom("64faeaa2e3cbadaf82d8fa8c7ded508cb043c5d101671f43c084be2ac6163148", 1, "76a914343cadc47d08a14ef773d70b3b2a90870b67b3ad88ac", 5000000000, nil),
				)
				tx.Inputs[0].SequenceNumber = 0xfffffffe

				script1, err := script.NewFromHex("76a9140108b364bbbddb222e2d0fac1ad4f6f86b10317688ac")
				require.NoError(t, err)
				tx.AddOutput(&transaction.TransactionOutput{
					Satoshis:      2200000000,
					LockingScript: script1,
				})

				script2, err := script.NewFromHex("76a9143ac52294c730e7a4e9671abe3e7093d8834126ed88ac")
				require.NoError(t, err)
				tx.AddOutput(&transaction.TransactionOutput{
					Satoshis:      2799998870,
					LockingScript: script2,
				})
				return tx
			}(),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tx := test.tx

			priv, err := ec.PrivateKeyFromWif("cNGwGSc7KRrTmdLUZ54fiSXWbhLNDc2Eg5zNucgQxyQCzuQ5YRDq")
			require.NoError(t, err)

			unlocker, err := p2pkh.Unlock(priv, nil)
			require.NoError(t, err)
			uscript, err := unlocker.Sign(tx, 0)
			require.NoError(t, err)

			tx.Inputs[0].UnlockingScript = uscript
			parts, err := script.DecodeScript(*tx.Inputs[0].UnlockingScript)
			require.NoError(t, err)

			sigBytes := parts[0].Data
			publicKeyBytes := parts[1].Data

			publicKey, err := ec.ParsePubKey(publicKeyBytes)
			require.NoError(t, err)

			sig, err := ec.ParseDERSignature(sigBytes)
			require.NoError(t, err)

			sh, err := tx.CalcInputSignatureHash(0, sighash.AllForkID)
			require.NoError(t, err)

			require.True(t, sig.Verify(sh, publicKey))
		})
	}
}
