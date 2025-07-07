package chaintracker

import (
	"context"

	"github.com/bsv-blockchain/go-sdk/chainhash"
)

type ChainTracker interface {
	IsValidRootForHeight(ctx context.Context, root *chainhash.Hash, height uint32) (bool, error)
	CurrentHeight(ctx context.Context) (uint32, error)
}
