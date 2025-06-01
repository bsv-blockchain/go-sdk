# Create Transaction with Inscription Example

This example demonstrates how to use the `transaction` and `script` packages to create a Bitcoin SV transaction that includes an "inscription" output, embedding arbitrary data (like an image) onto the blockchain.

## Overview

The `create_tx_with_inscription` example showcases:
1. Creating a new transaction.
2. Adding an input from a previous transaction (UTXO).
3. Reading data from a file (an image in this case).
4. Determining the MIME type of the data.
5. Using `tx.Inscribe()` to create an OP_RETURN output formatted as a BRC-43 (1Sat Ordinals style) inscription. This output contains the file data and its content type.
6. Adding a change output.
7. Signing the transaction.

## Code Walkthrough

### Creating and Signing the Inscription Transaction

```go
// Create a new transaction and add an input
priv, _ := ec.PrivateKeyFromWif("KznpA63DPFrmHecASyL6sFmcRgrNT9oM8Ebso8mwq1dfJF3ZgZ3V")
unlocker, _ := p2pkh.Unlock(priv, nil)
tx := transaction.NewTransaction()
_ = tx.AddInputFrom( /* UTXO details */ unlocker)

// Read image data and get content type
data, _ := os.ReadFile("1SatLogoLight.png")
contentType := mime.TypeByExtension(".png")

// Create a P2PKH locking script for the inscription output itself (where the 1 satoshi for the inscription goes)
add, _ := script.NewAddressFromPublicKey(priv.PubKey(), true)
inscriptionLockingScript, _ := p2pkh.Lock(add)

// Inscribe the data
err = tx.Inscribe(&script.InscriptionArgs{
    LockingScript: inscriptionLockingScript, // Who owns this inscription
    Data:          data,
    ContentType:   contentType,
})
// ... handle error ...

// Add a change output
changeAdd, _ := script.NewAddressFromString("17ujiveRLkf2JQiGR8Sjtwb37evX7vG3WG")
changeScript, _ := p2pkh.Lock(changeAdd)
tx.AddOutput(&transaction.TransactionOutput{
    LockingScript: changeScript,
    Satoshis:      0, // Will be calculated if tx.FeePerKB > 0
    Change:        true,
})

// Sign the transaction
err = tx.Sign()
// ... handle error ...

fmt.Println(tx.String()) // Print the raw transaction hex
```

This section shows the process of:
- Setting up a private key and deriving an unlocker for the input.
- Adding a spendable input (UTXO).
- Reading the content of `1SatLogoLight.png` and its MIME type.
- Creating a P2PKH locking script that will "own" the inscription.
- Calling `tx.Inscribe()` which constructs the specific OP_FALSE OP_IF ... OP_ENDIF script sequence for the inscription, placing the data and content type within it. This method adds the inscription output to the transaction.
- Adding a standard P2PKH change output.
- Signing all inputs of the transaction.

## Running the Example

To run this example:
1. Ensure you have the `1SatLogoLight.png` file in the same directory as `create_tx_with_inscription.go`.
2. Execute the Go program:
```bash
go run create_tx_with_inscription.go
```
The output will be the hexadecimal representation of the signed transaction.

**Note**:
- The example uses a hardcoded private key and UTXO details. For a real transaction, you would use your own keys and unspent outputs.
- The transaction created by this example is not broadcast to the network. You would need to use a broadcasting service to do that.
- The `tx.Inscribe()` method creates a 1-satoshi output locked with `inscriptionLockingScript`, followed by the inscription OP_RETURN output.
- The change output amount will be automatically calculated if `tx.FeePerKB` is set to a value greater than 0 before signing. If `tx.FeePerKB` is 0 (the default), the change output will receive any remaining satoshis after accounting for inputs and other outputs (like the 1-satoshi inscription output).

## Integration Steps

To create an inscription transaction in your application:
1. Obtain a spendable UTXO and the corresponding private key.
2. Create a `transaction.NewTransaction()`.
3. Add the input using `tx.AddInputFrom()` or similar, providing an appropriate `UnlockingScriptGetter`.
4. Prepare your data (`[]byte`) and determine its `contentType` (MIME string).
5. Create the `LockingScript` that will be associated with the 1-satoshi output for the inscription (i.e., who owns the inscription). This is typically a P2PKH script.
6. Call `tx.Inscribe(&script.InscriptionArgs{LockingScript: yourLockingScript, Data: data, ContentType: contentType})`.
7. Add any other outputs, including a change output (`tx.AddOutput(&transaction.TransactionOutput{LockingScript: changeScript, Change: true})`).
8. Set transaction fee parameters if desired (e.g., `tx.FeePerKB = fee_models.DefaultFee().FeeKB`).
9. Sign the transaction using `tx.Sign()`.
10. Broadcast the resulting `tx.String()` (hex) or `tx.Bytes()`.

## Additional Resources

For more information, see:
- [Package Documentation - Transaction](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/transaction)
- [Package Documentation - Script](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/script)
- [Create Transaction with OP_RETURN Example](../create_tx_with_op_return/)
- BRC-43 (Ordinals Inscriptions on BSV) specification.
