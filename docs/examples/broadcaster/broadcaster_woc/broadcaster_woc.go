package main

import (
	"github.com/bsv-blockchain/go-sdk/v2/transaction"
	"github.com/bsv-blockchain/go-sdk/v2/transaction/broadcaster"
)

func main() {

	// Create a new transaction
	hexTx := "010000000100"
	tx, _ := transaction.NewTransactionFromHex(hexTx)

	// Use the WOC API broadcaster
	b := &broadcaster.WhatsOnChain{
		ApiKey:  "",
		Network: broadcaster.WOCMainnet,
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
