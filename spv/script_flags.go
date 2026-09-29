package spv

import (
	"context"
	"math"

	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
)

// unminedHeight is the height used for a transaction that is not in a block:
// it can only be mined above every activation height.
const unminedHeight = math.MaxUint32

// ActivationHeightsProvider is implemented by a chain tracker that knows
// which network it follows, so that Verify applies that network's script
// rules to the outputs a transaction spends. chaintracker.WhatsOnChain and
// headers_client.Client implement it, and WithActivationHeights adds it to
// any chain tracker. Verify takes a chain tracker that does not implement it
// to follow mainnet.
type ActivationHeightsProvider interface {
	ActivationHeights() scriptflag.ActivationHeights
}

// WithActivationHeights returns a chain tracker that answers queries with
// chainTracker and reports heights as the activation heights of the network
// it follows, for verifying transactions of a network other than mainnet
// with a chain tracker that does not implement ActivationHeightsProvider.
// The zero value of heights makes every rule active from the first block.
// Verify still finds any other optional interface chainTracker implements,
// such as MedianTimePastProvider. chainTracker must not be nil.
func WithActivationHeights(chainTracker chaintracker.ChainTracker, heights scriptflag.ActivationHeights) chaintracker.ChainTracker {
	if chainTracker == nil {
		panic("spv: WithActivationHeights needs a chain tracker")
	}
	return &networkTracker{ChainTracker: chainTracker, heights: heights}
}

// networkTracker is a chain tracker with the activation heights of the
// network it follows.
type networkTracker struct {
	chaintracker.ChainTracker

	heights scriptflag.ActivationHeights
}

func (n *networkTracker) ActivationHeights() scriptflag.ActivationHeights {
	return n.heights
}

// activationHeights returns the activation heights of the network that
// chainTracker follows, taking mainnet when the tracker does not say.
func activationHeights(chainTracker chaintracker.ChainTracker) scriptflag.ActivationHeights {
	if p, ok := trackerAs[ActivationHeightsProvider](chainTracker); ok {
		return p.ActivationHeights()
	}
	return scriptflag.MainNetActivationHeights
}

// trackerAs returns chainTracker as a T, or else the first tracker it wraps
// through WithActivationHeights that is one, so that wrapping a tracker only
// changes its activation heights.
func trackerAs[T any](chainTracker chaintracker.ChainTracker) (T, bool) {
	for {
		if p, ok := chainTracker.(T); ok {
			return p, true
		}
		n, ok := chainTracker.(*networkTracker)
		if !ok {
			var zero T
			return zero, false
		}
		chainTracker = n.ChainTracker
	}
}

// MedianTimePastProvider is implemented by a chain tracker that reports the
// median time past of the chain tip, the median timestamp of its last 11
// blocks, against which bitcoin-sv checks a time-based nLockTime (IsFinalTx,
// validation.cpp:228-248). Verify rejects a transaction with a non-final
// input under a time-based nLockTime unless chainTracker, or the tracker
// WithActivationHeights wraps, implements it. chaintracker.WhatsOnChain and
// headers_client.Client do not.
type MedianTimePastProvider interface {
	MedianTimePast(ctx context.Context) (uint32, error)
}
