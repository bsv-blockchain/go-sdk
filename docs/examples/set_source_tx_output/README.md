# Setting Source Transaction Outputs for Inputs

When signing transactions without full BEEF (source transactions), you must provide the previous output details for each input.

- Problem: You used a UTXO API and do not have the source transaction payload.
- Solution: For each input, fetch satoshis and locking script of the referenced outpoint and call `SetSourceTxOutput`.

Example (Go):

```go
// Given a transaction tx and an input at index 0
lockingScript, _ := script.NewFromHex("76a914...88ac")
tx.Inputs[0].SetSourceTxOutput(&transaction.TransactionOutput{
    Satoshis:      15564838601,
    LockingScript: lockingScript,
})

unlocker, _ := p2pkh.Unlock(priv, nil)
us, _ := unlocker.Sign(tx, 0)
tx.Inputs[0].UnlockingScript = us
```

This ensures signature-hash calculation has the required context (value + script) and allows `Sign` to work.

## Alternative: Provide the source output when adding the input

If you already have the previous output details at the time you add the input, you can use `AddInputWithOutput` to attach the source output inline. This avoids a separate `SetSourceTxOutput` call:

```go
tx := transaction.NewTransaction()
unlocker, _ := p2pkh.Unlock(priv, nil)

txid, _ := chainhash.NewHashFromHex("<prev-txid-hex>")
lockingScript, _ := script.NewFromHex("76a914...88ac")

tx.AddInputWithOutput(&transaction.TransactionInput{
    SourceTXID:              txid,
    SourceTxOutIndex:        0,
    UnlockingScriptTemplate: unlocker,
}, &transaction.TransactionOutput{
    LockingScript: lockingScript,
    Satoshis:      15564838601,
})

// Now you can sign the transaction
_ = tx.Sign()
```

See also: `docs/examples/create_tx_with_op_return/create_tx_with_op_return.go` for a complete working example of this approach.
