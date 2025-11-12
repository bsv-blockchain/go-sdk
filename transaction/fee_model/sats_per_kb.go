package feemodel

import (
	"math"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
)

type SatoshisPerKilobyte struct {
	Satoshis uint64
}

func (s *SatoshisPerKilobyte) ComputeFee(tx *transaction.Transaction) (uint64, error) {
	size := 4
	size += util.VarInt(len(tx.Inputs)).Length()
	for vin, i := range tx.Inputs {
		size += 40
		if i.UnlockingScript != nil && len(*i.UnlockingScript) > 0 {
			scriptLen := len(*i.UnlockingScript)
			size += util.VarInt(scriptLen).Length() + scriptLen
		} else if i.UnlockingScriptTemplate != nil {
			scriptLen := int(i.UnlockingScriptTemplate.EstimateLength(tx, uint32(vin)))
			size += util.VarInt(scriptLen).Length() + scriptLen
		} else {
			return 0, ErrNoUnlockingScript
		}
	}
	size += util.VarInt(len(tx.Outputs)).Length()
	for _, o := range tx.Outputs {
		size += 8
		size += util.VarInt(len(*o.LockingScript)).Length()
		size += len(*o.LockingScript)
	}
	size += 4
	return (uint64(math.Ceil(float64(size)/1000)) * s.Satoshis), nil
}
