package transaction

import (
	"github.com/bsv-blockchain/go-sdk/script"
)

type UnlockingScriptTemplate interface {
	Sign(tx *Transaction, inputIndex uint32) (*script.Script, error)
	EstimateLength(tx *Transaction, inputIndex uint32) uint32
}
