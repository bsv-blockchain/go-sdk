// Copyright (c) 2024 The bsv-blockchain/go-sdk developers
// Use of this source code is governed by an ISC license that can be found in the LICENSE file.

// Tests derived from the BSV node v1.2.0 Chronicle upgrade functional test
// sighash_chronicle.py:
// https://github.com/bitcoin-sv/bitcoin-sv/tree/172c8fa38cce30cf4df0327b33c7418ea6289de8/test/functional/chronicle_upgrade_tests
//
// SIGHASH_CHRONICLE alongside SIGHASH_FORKID selects the original transaction
// digest. It is a legal hash type post-Chronicle and an illegal one before.

package interpreter

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

func chronicleKey(seed string) (*ec.PrivateKey, []byte) {
	priv, pub := ec.PrivateKeyFromBytes(crypto.Sha256([]byte(seed)))
	return priv, pub.Compressed()
}

// chronicleSign signs input 0 of tx over scriptCode with the given sighash flag.
func chronicleSign(t *testing.T, tx *transaction.Transaction, scriptCode *script.Script, flag sighash.Flag, key *ec.PrivateKey) []byte {
	t.Helper()
	out := tx.Inputs[0].SourceTxOutput()
	saved := out.LockingScript
	out.LockingScript = scriptCode
	hash, err := tx.CalcInputSignatureHash(0, flag)
	out.LockingScript = saved
	require.NoError(t, err)
	sig, err := key.Sign(hash)
	require.NoError(t, err)
	return append(sig.Serialize(), byte(flag))
}

// chronicleP2PKTx builds a version 2 transaction spending a <pubKey> OP_CHECKSIG output.
func chronicleP2PKTx(t *testing.T, pubKey []byte) (*transaction.Transaction, *transaction.TransactionOutput) {
	t.Helper()
	lock := buildScript(t, pubKey, script.OpCHECKSIG)
	prevOut := &transaction.TransactionOutput{Satoshis: 100000, LockingScript: lock}
	tx := &transaction.Transaction{
		Version: 2,
		Inputs: []*transaction.TransactionInput{{
			SourceTXID:       &chainhash.Hash{1},
			SourceTxOutIndex: 0,
			SequenceNumber:   0xffffffff,
		}},
		Outputs: []*transaction.TransactionOutput{{Satoshis: 99900, LockingScript: lock}},
	}
	tx.Inputs[0].SetSourceTxOutput(prevOut)
	return tx, prevOut
}

func TestChronicleSighashChronicle(t *testing.T) {
	key, pubKey := chronicleKey("utxo")

	tests := map[string]struct {
		flag     sighash.Flag
		preValid bool
	}{
		"ALL|FORKID":                        {sighash.AllForkID, true},
		"ALL|FORKID|CHRONICLE":              {sighash.AllForkID | sighash.Chronicle, false},
		"SINGLE|FORKID|CHRONICLE":           {sighash.SingleForkID | sighash.Chronicle, false},
		"ALL|FORKID|CHRONICLE|ANYONECANPAY": {sighash.AllForkID | sighash.Chronicle | sighash.AnyOneCanPay, false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tx, prevOut := chronicleP2PKTx(t, pubKey)
			tx.Inputs[0].UnlockingScript = buildScript(t, chronicleSign(t, tx, prevOut.LockingScript, tc.flag, key))

			require.NoError(t, NewEngine().Execute(WithTx(tx, 0, prevOut), WithForkID(), WithAfterChronicle()))

			err := NewEngine().Execute(WithTx(tx, 0, prevOut), WithForkID(), WithAfterGenesis())
			if tc.preValid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
