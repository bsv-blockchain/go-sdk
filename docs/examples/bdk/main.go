//go:build cgo && !ios && !android && (darwin || linux) && (amd64 || arm64)

package main

import (
	"log"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/bdk"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

func main() {
	privateKey, err := ec.PrivateKeyFromWif("cNGwGSc7KRrTmdLUZ54fiSXWbhLNDc2Eg5zNucgQxyQCzuQ5YRDq")
	if err != nil {
		log.Fatal(err)
	}
	address, err := script.NewAddressFromPublicKey(privateKey.PubKey(), true)
	if err != nil {
		log.Fatal(err)
	}
	lockingScript, err := p2pkh.Lock(address)
	if err != nil {
		log.Fatal(err)
	}
	unlocker, err := p2pkh.Unlock(privateKey, nil)
	if err != nil {
		log.Fatal(err)
	}

	tx := transaction.NewTransaction()
	if err = tx.AddInputFrom(
		"45be95d2f2c64e99518ffbbce03fb15a7758f20ee5eecf0df07938d977add71d",
		0,
		lockingScript.String(),
		1000,
		unlocker,
	); err != nil {
		log.Fatal(err)
	}
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      900,
		LockingScript: lockingScript,
	})

	// Installation changes all SDK secp256k1 signing and verification calls.
	bdk.InstallSignatureBackend()
	defer bdk.ResetSignatureBackend()
	if err = tx.Sign(); err != nil {
		log.Fatal(err)
	}

	validator, err := bdk.NewValidator("main")
	if err != nil {
		log.Fatal(err)
	}
	validator.Native().SetRequireStandard(true)

	// Each input needs the height of the UTXO it spends. consensus=false
	// requests both policy and consensus validation.
	if err = validator.ValidateTransaction(tx, []int32{899999}, 900000, false); err != nil {
		log.Fatal(err)
	}

	log.Print("BDK validation succeeded")
}
