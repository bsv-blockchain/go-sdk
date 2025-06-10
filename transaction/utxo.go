package transaction

import (
	"github.com/bsv-blockchain/go-sdk/chainhash"
	script "github.com/bsv-blockchain/go-sdk/script"
)

// UTXO an unspent transaction output, used for creating inputs
type UTXO struct {
	TxID                    *chainhash.Hash         `json:"txid"`
	Vout                    uint32                  `json:"vout"`
	LockingScript           *script.Script          `json:"locking_script"`
	Satoshis                uint64                  `json:"satoshis"`
	UnlockingScriptTemplate UnlockingScriptTemplate `json:"-"`
}

// UTXOs a collection of *transaction.UTXO.
type UTXOs []*UTXO

// LockingScriptHex retur nthe locking script in hex format.
func (u *UTXO) LockingScriptHex() string {
	return u.LockingScript.String()
}

// NewUTXO creates a new UTXO.
func NewUTXO(prevTxID string, vout uint32, prevTxLockingScript string, satoshis uint64) (*UTXO, error) {
	pts, err := script.NewFromHex(prevTxLockingScript)
	if err != nil {
		return nil, err
	}
	pti, err := chainhash.NewHashFromHex(prevTxID)
	if err != nil {
		return nil, err
	}

	return &UTXO{
		TxID:          pti,
		Vout:          vout,
		LockingScript: pts,
		Satoshis:      satoshis,
	}, nil
}
