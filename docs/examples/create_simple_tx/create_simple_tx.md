# Example: Creating a Simple Transaction

This guide walks you through the steps of creating a simple Bitcoin transaction. To get started, let's explain some basic concepts around Bitcoin transactions.

## Understanding and Creating Transactions

Transactions in Bitcoin are mechanisms for transferring value and invoking smart contract logic. The Transaction class in the BSV SDK encapsulates the creation, signing, and broadcasting of transactions, also enabling the use of Bitcoin's scripting language for locking and unlocking coins.

## Creating and Signing a Transaction

Consider the scenario where you need to create a transaction. The process involves specifying inputs (where the bitcoins are coming from) and outputs (where they're going). Here's a simplified example:

``` go
package main

import (
 "context"
 "log"

 wif "github.com/bsv-blockchain/go-sdk/compat/wif"
 "github.com/bsv-blockchain/go-sdk/transaction"
 "github.com/bsv-blockchain/go-sdk/transaction/unlocker"
)

// https://goplay.tools/snippet/bnsS-pA56ob
func main() {
 // Create a new transaction
   tx := transaction.NewTransaction()

   // Add the inputs
   unlockingScriptTemplate, _ := p2pkh.Unlock(priv, nil)
   if err := tx.AddInputFrom(
		"11b476ad8e0a48fcd40807a111a050af51114877e09283bfa7f3505081a1819d",
		0,
		"76a9144bca0c466925b875875a8e1355698bdcc0b2d45d88ac",
		1500,
		unlockingScriptTemplate,
	); err!= nil {
      log.Fatal(err.Error())
   }

   // Add the outputs
   _ = tx.PayToAddress(
      // Destination address
      "1NRoySJ9Lvby6DuE2UQYnyT67AASwNZxGb",
      // Value in satoshis
      1000,
   )

   priv, _ := ec.PrivateKeyFromWif("KznvCNc6Yf4iztSThoMH6oHWzH9EgjfodKxmeuUGPq5DEX5maspS")

   // Sign the transaction
   if err := tx.Sign(); err != nil {
		log.Fatal(err.Error())
	}
   log.Printf("tx: %s\n", tx)
}

```

### Package and Imports

The program is defined in the main package.
It imports necessary packages for handling the transaction, including context management, logging, WIF (Wallet Import Format) decoding, and transaction-related functionalities from the go-sdk.
Main Function:

`transaction.NewTransaction()` creates a new, empty transaction.

`tx.AddInputFrom(...)` adds an input to the transaction. This input includes:

- The transaction ID (txid) from which the input is being spent.
- The output index (vout) in the referenced transaction.
- A script (locking script) representing the locking conditions under which the output can be spent.
- The number of satoshis from the output that is being spent.
- UnlockingScriptTemplate used to sign input

`tx.PayToAddress(...)` adds an output to the transaction, specifying:

- The recipient's Bitcoin SV address.
- The amount of satoshis to send to that address.

`ec.PrivateKeyFromWif(...)` decodes a WIF-encoded private key. This is necessary for signing the transaction inputs.

`tx.Sign(...)` attempts to sign all inputs of the transaction using the script templates provided. This is essential for validating the transaction on the network.

The context passed `(context.Background())` is the default context which is empty but can be used to control cancellations and timeouts.
Error Handling and Logging:

If `tx.Sign(...)` returns an error, the program logs the error and terminates using `log.Fatal(...)`.

If no error occurs, it logs the serialized form of the transaction, which is ready to be broadcasted to the network.
