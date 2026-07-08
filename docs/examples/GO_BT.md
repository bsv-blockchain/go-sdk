# Convert from libsv/go-bt transaction

For users of libsv/go-bt library, this function illustrates the differences between the two transaction structures and converts from one to the other.

```go
func GoBt2GoSDKTransaction(tx *bt.Tx) *transaction.Transaction {
    sdkTx := &transaction.Transaction{
        Version:  tx.Version,
        LockTime: tx.LockTime,
    }

    sdkTx.Inputs = make([]*transaction.TransactionInput, len(tx.Inputs))
    for i, in := range tx.Inputs {
        sdkTx.Inputs[i] = &transaction.TransactionInput{
            SourceTXID:       bt.ReverseBytes(in.PreviousTxID()),
            SourceTxOutIndex: in.PreviousTxOutIndex,
            UnlockingScript:  (*script.Script)(in.UnlockingScript),
            SequenceNumber:   in.SequenceNumber,
        }
    }

    sdkTx.Outputs = make([]*transaction.TransactionOutput, len(tx.Outputs))
    for i, out := range tx.Outputs {
        sdkTx.Outputs[i] = &transaction.TransactionOutput{
            Satoshis:      out.Satoshis,
            LockingScript: (*script.Script)(out.LockingScript),
        }
    }

    return sdkTx
}
```
