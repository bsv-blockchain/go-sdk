package main

import (
	"log"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	script "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

// Example: Setting source transaction outputs on inputs when you don't have full BEEF
// Problem: You have UTXOs from an API, but not the full source transactions.
// Solution: For each input, look up the previous output (satoshis + locking script)
//           and set it via SetSourceTxOutput. This enables sighash calculation and signing.
func main() {
	// Create a transaction
	tx := transaction.NewTransaction()

	// Add an input from an outpoint (no script/satoshis provided here)
	if err := tx.AddInputFrom("45be95d2f2c64e99518ffbbce03fb15a7758f20ee5eecf0df07938d977add71d", 0, "", 0, nil); err != nil {
		log.Fatal(err)
	}

	// Fetch the source output details from your data provider
	// For the example, we build them locally
	lockingScript, err := script.NewFromHex("76a914c7c6987b6e2345a6b138e3384141520a0fbc18c588ac")
	if err != nil {
		log.Fatal(err)
	}
	// Attach source output to input 0
	tx.Inputs[0].SetSourceTxOutput(&transaction.TransactionOutput{
		Satoshis:      15564838601,
		LockingScript: lockingScript,
	})

	// Sign input 0 with a private key
	priv, err := ec.PrivateKeyFromWif("cNGwGSc7KRrTmdLUZ54fiSXWbhLNDc2Eg5zNucgQxyQCzuQ5YRDq")
	if err != nil {
		log.Fatal(err)
	}
	unlocker, err := p2pkh.Unlock(priv, nil)
	if err != nil {
		log.Fatal(err)
	}
	us, err := unlocker.Sign(tx, 0)
	if err != nil {
		log.Fatal(err)
	}
	tx.Inputs[0].UnlockingScript = us
}
