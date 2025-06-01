# Create Transaction with OP_RETURN Example

This example demonstrates how to use the `transaction` package to create a Bitcoin SV transaction that includes an `OP_RETURN` output, allowing for the embedding of arbitrary data on the blockchain.

## Overview

The `create_tx_with_op_return` example showcases:
1. Creating a new transaction.
2. Adding an input from a previous transaction (UTXO), specifying its locking script and value, along with an unlocker derived from a private key.
3. Using `tx.AddOpReturnOutput()` to add a new output that contains a standard `OP_RETURN` script with custom data.
4. Signing the transaction.

## Code Walkthrough

### Creating and Signing the Transaction

```go
// Define private key and derive unlocker
priv, _ := ec.PrivateKeyFromWif("L3VJH2hcRGYYG6YrbWGmsxQC1zyYixA82YjgEyrEUWDs4ALgk8Vu")
p2pkhUnlocker, err := p2pkh.Unlock(priv, nil)
// ... handle error ...

// Create a new transaction
tx := transaction.NewTransaction()

// Define UTXO details
txid, _ := chainhash.NewHashFromHex("b7b0650a7c3a1bd4716369783876348b59f5404784970192cec1996e86950576")
lockingScript, _ := script.NewFromHex("76a9149cbe9f5e72fa286ac8a38052d1d5337aa363ea7f88ac")
satoshis := uint64(1000)

// Add the input
tx.AddInputWithOutput(&transaction.TransactionInput{
    SourceTXID:              txid,
    SourceTxOutIndex:        0,
    UnlockingScriptTemplate: p2pkhUnlocker,
}, &transaction.TransactionOutput{
    LockingScript: lockingScript,
    Satoshis:      satoshis,
})

// Add an OP_RETURN output with custom data
_ = tx.AddOpReturnOutput([]byte("You are using go-sdk!"))

// Sign the transaction
if err := tx.Sign(); err != nil {
    log.Fatal(err.Error())
}

log.Println("tx: ", tx.String()) // Print the raw transaction hex
```

This section details:
- Loading a private key from WIF format.
- Creating a P2PKH unlocker from this private key.
- Initializing a new transaction.
- Adding a specific UTXO as an input by providing its transaction ID, output index, the original locking script, its satoshi value, and the unlocker.
- Calling `tx.AddOpReturnOutput()` with a byte slice containing the desired data. This method constructs the `OP_RETURN` script and adds it as a new output to the transaction.
- Signing all inputs of the transaction.

## Running the Example

To run this example:

```bash
go run create_tx_with_op_return.go
```
The output will be the hexadecimal representation of the signed transaction containing the `OP_RETURN` output.

**Note**:
- The example uses a hardcoded private key and UTXO details. In a real application, you would use your own keys and actual unspent outputs from the blockchain.
- The transaction created is not broadcast. A separate mechanism (e.g., a broadcasting client or service) would be needed to send it to the Bitcoin SV network.
- `OP_RETURN` outputs are unspendable and are typically used for data storage. They do not require a change output in this simple example if the input satoshis exactly cover the fees. If there were other spendable outputs or a desire for explicit fee control and change, a change output would typically be added.

## Integration Steps

To create a transaction with an `OP_RETURN` output in your application:
1. Identify a spendable UTXO and the private key needed to unlock it.
2. Create a `transaction.NewTransaction()`.
3. Add the input using `tx.AddInputWithOutput()` (if you know the previous output's script and value) or `tx.AddInputFrom()` (which requires a `UnlockingScriptGetter` that can fetch this information).
4. Prepare your data as `[]byte`.
5. Call `tx.AddOpReturnOutput(yourData)` to add the data output.
6. Add any other necessary outputs (e.g., payments to other parties, change output).
7. Set transaction fee parameters if desired (e.g., `tx.FeePerKB`).
8. Sign the transaction using `tx.Sign()`.
9. Broadcast the transaction hex.

## Additional Resources

For more information, see:
- [Package Documentation - Transaction](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/transaction)
- [Package Documentation - Script](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/script)
- [Create Simple Transaction Example](../create_simple_tx/)
- [Create Transaction with Inscription Example](../create_tx_with_inscription/)
