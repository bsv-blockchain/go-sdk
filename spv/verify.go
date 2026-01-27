package spv

import (
	"context"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
)

func Verify(ctx context.Context, t *transaction.Transaction,
	chainTracker chaintracker.ChainTracker,
	feeModel transaction.FeeModel) (bool, error) {
	verifiedTxids := make(map[string]struct{})
	txQueue := []*transaction.Transaction{t}
	if chainTracker == nil {
		chainTracker = chaintracker.NewWhatsOnChain(chaintracker.MainNet, "")
	}

	// Validate fees only on the root transaction, not ancestors
	if feeModel != nil {
		txFee, err := t.GetFee()
		if err != nil {
			return false, err
		}
		requiredFee, err := feeModel.ComputeFee(t)
		if err != nil {
			return false, err
		}
		if txFee < requiredFee {
			return false, fmt.Errorf("fee is too low: paid %d, required %d", txFee, requiredFee)
		}
	}

	for len(txQueue) > 0 {
		tx := txQueue[0]
		txQueue = txQueue[1:]
		txid := tx.TxID()
		txidStr := txid.String()

		if _, ok := verifiedTxids[txidStr]; ok {
			continue
		}

		if tx.MerklePath != nil {
			if isValid, err := tx.MerklePath.Verify(ctx, txid, chainTracker); err != nil {
				return false, err
			} else if isValid {
				verifiedTxids[txidStr] = struct{}{}
				continue
			} else {
				return false, fmt.Errorf("invalid merkle path for transaction %s", txidStr)
			}
		}

		inputTotal := uint64(0)
		for vin, input := range tx.Inputs {
			sourceOutput := input.SourceTxOutput()
			if sourceOutput == nil {
				return false, fmt.Errorf("input %d has no source transaction", vin)
			}
			inputTotal += sourceOutput.Satoshis

			if input.SourceTransaction != nil {
				if _, ok := verifiedTxids[input.SourceTransaction.TxID().String()]; !ok {
					txQueue = append(txQueue, input.SourceTransaction)
				}
			}

			if err := interpreter.NewEngine().Execute(
				interpreter.WithTx(tx, vin, sourceOutput),
				interpreter.WithForkID(),
				interpreter.WithAfterGenesis(),
			); err != nil {
				fmt.Println(err)
				return false, err
			}
		}
	}

	return true, nil
}

func VerifyScripts(ctx context.Context, t *transaction.Transaction) (bool, error) {
	return Verify(ctx, t, &GullibleHeadersClient{}, nil)
}
