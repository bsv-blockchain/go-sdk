package transaction

import (
	"github.com/bsv-blockchain/go-sdk/script"
)

type UnlockingScriptTemplate interface {
	Sign(tx *Transaction, inputIndex uint32) (*script.Script, error)
	EstimateLength(tx *Transaction, inputIndex uint32) uint32
}

// UnlockingScriptTemplateWithCache is an optional interface an unlocking-script
// template may implement to sign using a shared SigHashCache. When a template
// implements it, Transaction.Sign / SignUnsigned compute the BIP143 sighash
// midstate hashes once for the whole transaction and reuse them for every input,
// making signing O(N) instead of O(N^2). Templates that do not implement it are
// signed via Sign() exactly as before, so this is fully backward-compatible.
type UnlockingScriptTemplateWithCache interface {
	UnlockingScriptTemplate
	SignWithCache(tx *Transaction, inputIndex uint32, cache *SigHashCache) (*script.Script, error)
}
