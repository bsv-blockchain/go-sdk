package main

import (
	"encoding/hex"
	"fmt"
	"log"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	opcodes "github.com/bsv-blockchain/go-sdk/script"
	script "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

func main() {
	// Generating and Deserializing Scripts

	// From Hex
	opTrueHex := hex.EncodeToString([]byte{opcodes.OpTRUE})
	scriptFromHex, err := script.NewFromHex(opTrueHex)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Script from Hex:", scriptFromHex)

	// From ASM
	p2pkhScriptAsm := "OP_DUP OP_HASH160 1451baa3aad777144a0759998a03538018dd7b4b OP_EQUALVERIFY OP_CHECKSIG"
	scriptFromASM, err := script.NewFromASM(p2pkhScriptAsm)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Script from ASM:", scriptFromASM)

	// From Binary
	binaryData := []byte{opcodes.OpPUSHDATA1, 3, 1, 2, 3}
	scriptFromBinary := script.NewFromBytes(binaryData)
	fmt.Println("Script from Binary:", scriptFromBinary)

	// Advanced Example: Creating a P2PKH Locking Script
	privKey, err := ec.NewPrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	add, err := script.NewAddressFromPublicKey(privKey.PubKey(), true)
	if err != nil {
		log.Fatal(err)
	}

	lockingScript, err := p2pkh.Lock(add)
	if err != nil {
		log.Fatal(err)
	}
	lockingScriptASM := lockingScript.ToASM()
	log.Printf("Locking Script (ASM): %s\n", lockingScriptASM)

	// Serializing Scripts
	p2pkhScript := "OP_DUP OP_HASH160 1451baa3aad777144a0759998a03538018dd7b4b OP_EQUALVERIFY OP_CHECKSIG"
	script, err := script.NewFromASM(p2pkhScript)
	if err != nil {
		log.Fatal(err)
	}

	// Serialize script to Hex
	scriptAsHex := script.String()
	fmt.Println("Script as Hex:", scriptAsHex)

	// Serialize script to ASM
	scriptAsASM := script.ToASM()
	fmt.Println("Script as ASM:", scriptAsASM)

	// Serialize script to Binary
	scriptAsBinary, err := hex.DecodeString(script.String())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Script as Binary:", scriptAsBinary)
}
