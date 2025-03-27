package feemodel

import (
	"math"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

type SatoshisPerKilobyte struct {
	Satoshis uint64
}

func (s *SatoshisPerKilobyte) ComputeFee(tx *transaction.Transaction) (uint64, error) {
	size := 4
	size += transaction.VarInt(len(tx.Inputs)).Length()
	for vin, i := range tx.Inputs {
		size += 40
		if i.UnlockingScript != nil && len(*i.UnlockingScript) > 0 {
			scriptLen := len(*i.UnlockingScript)
			size += transaction.VarInt(scriptLen).Length() + scriptLen
		} else if i.UnlockingScriptTemplate != nil {
			scriptLen := int(i.UnlockingScriptTemplate.EstimateLength(tx, uint32(vin)))
			size += transaction.VarInt(scriptLen).Length() + scriptLen
		} else {
			return 0, ErrNoUnlockingScript
		}
	}
	size += transaction.VarInt(len(tx.Outputs)).Length()
	for _, o := range tx.Outputs {
		size += 8
		size += transaction.VarInt(len(*o.LockingScript)).Length()
		size += len(*o.LockingScript)
	}
	size += 4
	return (uint64(math.Ceil(float64(size) / 1000))) * s.Satoshis, nil
}
