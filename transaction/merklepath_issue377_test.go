package transaction

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
)

// Issue #377: a MerklePath holding a single lone leaf at an offset other than 0
// is a one-level path that lacks the sibling needed to climb the tree. Only a
// block containing just its coinbase yields a single-leaf path, and that leaf
// sits at offset 0 (the txid is the root). A lone leaf at any other offset must
// be rejected, matching @bsv/sdk. The shared TypeScript vector (block height
// 1234) with its offset byte changed from 00 to 01.
const (
	// Control: the legitimate single-coinbase vector, offset 0.
	loneLeafOffset0Hex = "fdd2040101000202ef57aa9f29c8141ae17935c88434457b2117890f23efba0d0e0cba7a7a37d5"
	// Bug: the identical leaf moved to offset 1 (no sibling present).
	loneLeafOffset1Hex = "fdd2040101010202ef57aa9f29c8141ae17935c88434457b2117890f23efba0d0e0cba7a7a37d5"
	// txid == expected root of the offset-0 (legitimate) path.
	loneLeafTxidHex = "d5377a7aba0c0e0dbaef230f8917217b453484c83579e11a14c8299faa57ef02"
)

func TestMerklePathLoneLeafOffsetZeroStillValid(t *testing.T) {
	txid, err := chainhash.NewHashFromHex(loneLeafTxidHex)
	require.NoError(t, err)

	mp, err := NewMerklePathFromHex(loneLeafOffset0Hex)
	require.NoError(t, err, "the legitimate single-coinbase path at offset 0 must parse")

	root, err := mp.ComputeRoot(txid)
	require.NoError(t, err, "a single leaf at offset 0 is the block's only transaction; its txid is the root")
	require.Equal(t, loneLeafTxidHex, root.String())
}

func TestMerklePathLoneLeafNonZeroOffsetRejected(t *testing.T) {
	txid, err := chainhash.NewHashFromHex(loneLeafTxidHex)
	require.NoError(t, err)

	// A lone leaf at offset 1 must be refused either at parse time or when its
	// root is computed. Before the fix the SDK parses it and ComputeRoot returns
	// the txid as if it were the root, so this assertion fails.
	mp, err := NewMerklePathFromHex(loneLeafOffset1Hex)
	if err != nil {
		// Rejected at parse time: correct.
		return
	}
	root, err := mp.ComputeRoot(txid)
	require.Error(t, err,
		"a lone leaf at offset 1 lacks its sibling and must not yield a root (got %v)", root)
}
