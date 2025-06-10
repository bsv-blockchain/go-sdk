package transaction

import (
	"github.com/bsv-blockchain/go-sdk/v2/chainhash"
)

// DataFormat represents the format of the data in a BeefTx.
type DataFormat int

const (
	RawTx DataFormat = iota
	RawTxAndBumpIndex
	TxIDOnly
)

// BeefTx represents a Transaction or Txid within a Beef with or without reference to a BUMP.
type BeefTx struct {
	DataFormat  DataFormat
	KnownTxID   *chainhash.Hash
	Transaction *Transaction
	BumpIndex   int
	InputTxids  []*chainhash.Hash
}
