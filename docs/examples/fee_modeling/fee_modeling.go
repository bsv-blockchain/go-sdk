package feemodeling

import (
	"math"

	"github.com/bsv-blockchain/go-sdk/v2/transaction"
	"github.com/bsv-blockchain/go-sdk/v2/util"
)

type Example struct {
	Value int
}

func (e *Example) ComputeFee(tx transaction.Transaction) uint64 {
	// Version 3301 transactions are free :)
	if tx.Version == 3301 {
		return 0
	}

	// Compute the (potentially estimated) size of the transaction
	size := 4                                            // version
	size += util.VarInt(uint64(len(tx.Inputs))).Length() // number of inputs
	for i := 0; i < len(tx.Inputs); i++ {
		input := tx.Inputs[i]
		size += 40 // txid, output index, sequence number
		var scriptLength int
		if input.UnlockingScript != nil {
			scriptLength = len(*input.UnlockingScript)
		} else {
			panic("All inputs must have an unlocking script or an unlocking script template for sat/kb fee computation.")
		}
		size += util.VarInt(scriptLength).Length() // unlocking script length
		size += scriptLength                       // unlocking script
	}
	size += util.VarInt(len(tx.Outputs)).Length() // number of outputs
	for _, out := range tx.Outputs {
		size += 8 // satoshis
		length := len(*out.LockingScript)
		size += util.VarInt(length).Length() // script length
		size += length                       // script
	}
	size += 4 // lock time
	fee := float64((size / 1000) * e.Value)

	// Now we apply our input and output rules
	// For the inputs incentive
	if uint64(len(tx.Inputs))/3 >= uint64(len(tx.Outputs)) {
		fee *= 0.8
	}
	// For the outputs penalty
	if uint64(len(tx.Outputs))/5 >= uint64(len(tx.Inputs)) {
		fee *= 1.1
	}

	// We'll use Math.ceil to ensure the miners get the extra satoshi.
	return uint64(math.Ceil(fee))
}
