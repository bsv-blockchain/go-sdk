package chaintracker

import "github.com/bsv-blockchain/go-sdk/chainhash"

type ChainTracker interface {
	IsValidRootForHeight(root *chainhash.Hash, height uint32) (bool, error)
}
