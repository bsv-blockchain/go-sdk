package spv

import (
	"context"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
)

// memoTracker memoizes a chain tracker within one Verify call. Walking a
// graph can ask the same question many times over: N parsed copies of one
// mined parent verify the same merkle path N times, and several
// transactions from one block share a height. memoTracker asks the wrapped
// tracker at most once for each distinct (root, height) pair given to
// IsValidRootForHeight, and at most once for CurrentHeight. It caches true
// and false results but not errors, so a transient failure can be retried.
//
// memoTracker does not implement ActivationHeightsProvider: Verify reads the
// activation heights from the caller's chainTracker before wrapping it in a
// memoTracker, so that lookup still sees the tracker the caller gave it.
type memoTracker struct {
	chaintracker.ChainTracker

	roots  map[rootHeight]bool
	height *uint32
}

// rootHeight is the key IsValidRootForHeight results are memoized under.
type rootHeight struct {
	root   chainhash.Hash
	height uint32
}

// newMemoTracker returns a chain tracker that memoizes tracker's answers
// within its lifetime, which Verify limits to a single call.
func newMemoTracker(tracker chaintracker.ChainTracker) *memoTracker {
	return &memoTracker{ChainTracker: tracker, roots: make(map[rootHeight]bool)}
}

func (m *memoTracker) IsValidRootForHeight(ctx context.Context, root *chainhash.Hash, height uint32) (bool, error) {
	key := rootHeight{root: *root, height: height}
	if valid, ok := m.roots[key]; ok {
		return valid, nil
	}
	valid, err := m.ChainTracker.IsValidRootForHeight(ctx, root, height)
	if err != nil {
		return false, err
	}
	m.roots[key] = valid
	return valid, nil
}

func (m *memoTracker) CurrentHeight(ctx context.Context) (uint32, error) {
	if m.height != nil {
		return *m.height, nil
	}
	height, err := m.ChainTracker.CurrentHeight(ctx)
	if err != nil {
		return 0, err
	}
	m.height = &height
	return height, nil
}
