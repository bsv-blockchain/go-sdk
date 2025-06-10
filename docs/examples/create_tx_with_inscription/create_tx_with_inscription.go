package main

import (
	"fmt"
	"log"
	"mime"
	"os"

	ec "github.com/bsv-blockchain/go-sdk/v2/primitives/ec"
	script "github.com/bsv-blockchain/go-sdk/v2/script"
	"github.com/bsv-blockchain/go-sdk/v2/transaction"
	"github.com/bsv-blockchain/go-sdk/v2/transaction/template/p2pkh"
)

func main() {
	priv, _ := ec.PrivateKeyFromWif("KznpA63DPFrmHecASyL6sFmcRgrNT9oM8Ebso8mwq1dfJF3ZgZ3V")

	unlocker, err := p2pkh.Unlock(priv, nil) // get public key bytes and address
	if err != nil {
		fmt.Println(err)
		return
	}

	tx := transaction.NewTransaction()
	_ = tx.AddInputFrom(
		"39e5954ee335fdb5a1368ab9e851a954ed513f73f6e8e85eff5e31adbb5837e7",
		0,
		"76a9144bca0c466925b875875a8e1355698bdcc0b2d45d88ac",
		500,
		unlocker,
	)

	// Read the image file
	data, err := os.ReadFile("1SatLogoLight.png")
	if err != nil {
		fmt.Println(err)
		return
	}

	// Get the content type of the image
	contentType := mime.TypeByExtension(".png")
	add, err := script.NewAddressFromPublicKey(priv.PubKey(), true)
	if err != nil {
		fmt.Println(err)
		return
	}
	s, _ := p2pkh.Lock(add)
	err = tx.Inscribe(&script.InscriptionArgs{
		LockingScript: s,
		Data:          data,
		ContentType:   contentType,
	})
	if err != nil {
		log.Fatal(err)
	}

	changeAdd, _ := script.NewAddressFromString("17ujiveRLkf2JQiGR8Sjtwb37evX7vG3WG")

	changeScript, _ := p2pkh.Lock(changeAdd)
	tx.AddOutput(&transaction.TransactionOutput{
		LockingScript: changeScript,
		Change:        true,
	})

	err = tx.Sign()
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Println(tx.String())
}
