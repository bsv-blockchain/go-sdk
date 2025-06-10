package main

import (
	"github.com/bsv-blockchain/go-sdk/v2/transaction"
	"github.com/bsv-blockchain/go-sdk/v2/transaction/broadcaster"
)

func main() {

	// Create a new transaction
	hexTx := "010000000100"
	tx, _ := transaction.NewTransactionFromHex(hexTx)

	// Use the GP Arc Broadcaster

	b := &broadcaster.Arc{
		ApiUrl: "https://arc.gorillapool.io",
		ApiKey: "",
	}

	// Broadcast the transaction
	success, failure := tx.Broadcast(b)

	// Check for errors
	if failure != nil {
		panic(failure)
	}

	// Print the success message and transaction ID
	println(success.Message, success.Txid)
}
