package transaction

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
)

// TestComputeRootCharacterization cross-checks ComputeRoot against an
// independent reference root computed bottom-up by benchMerkleTree (which
// reduces with the separately byte-identity-tested MerkleTreeParent). It covers
// both a fully-populated BUMP (every node present, the state after absorbing
// many proofs) and each leaf's sparse proof BUMP, over a range of tree sizes.
//
// This pins ComputeRoot's output independently of its internal lookup
// mechanism, so a refactor of that mechanism is provably byte-identical.
func TestComputeRootCharacterization(t *testing.T) {
	t.Parallel()

	for _, leaves := range []int{2, 4, 8, 16, 256, 1024} {
		hashes := make([]*chainhash.Hash, 0, leaves)
		for i := range leaves {
			hashes = append(hashes, benchTx(uint32(i)).TxID())
		}
		levels := benchMerkleTree(hashes)
		wantRoot := levels[len(levels)-1][0]

		// Fully-populated BUMP: computing from any leaf yields the same root.
		full := benchFullBUMP(800000, levels)
		for i := range leaves {
			got, err := full.ComputeRoot(hashes[i])
			require.NoErrorf(t, err, "full leaves=%d idx=%d", leaves, i)
			require.Truef(t, got.Equal(*wantRoot), "full root leaves=%d idx=%d", leaves, i)
		}
		// nil txid auto-detects the first leaf and must agree.
		gotNil, err := full.ComputeRoot(nil)
		require.NoErrorf(t, err, "full nil leaves=%d", leaves)
		require.Truef(t, gotNil.Equal(*wantRoot), "full nil root leaves=%d", leaves)

		// Sparse proof BUMP: each leaf's own proof computes the same root.
		for i := range leaves {
			proof := benchProofBUMP(800000, levels, i)
			got, err := proof.ComputeRoot(hashes[i])
			require.NoErrorf(t, err, "proof leaves=%d idx=%d", leaves, i)
			require.Truef(t, got.Equal(*wantRoot), "proof root leaves=%d idx=%d", leaves, i)
		}

		// Single-level compound BUMP: only level 0 is present, so every interior
		// node is synthesized. This is the shape that exercises getOffsetLeaf's
		// lazy-index synthesis fallback and would be O(N^2) with a plain
		// linear-scan recursion; it must still compute the correct root.
		compound := singleLevelCompound(800000, hashes)
		for i := range leaves {
			got, err := compound.ComputeRoot(hashes[i])
			require.NoErrorf(t, err, "compound leaves=%d idx=%d", leaves, i)
			require.Truef(t, got.Equal(*wantRoot), "compound root leaves=%d idx=%d", leaves, i)
		}
	}
}

// singleLevelCompound builds a BUMP whose only level is the full leaf row, so
// ComputeRoot must synthesize every interior node from level 0.
func singleLevelCompound(blockHeight uint32, leaves []*chainhash.Hash) *MerklePath {
	isTxid := true
	level0 := make([]*PathElement, 0, len(leaves))
	for offset, h := range leaves {
		level0 = append(level0, &PathElement{Offset: uint64(offset), Hash: h, Txid: &isTxid})
	}
	return NewMerklePath(blockHeight, [][]*PathElement{level0})
}

// TestComputeRootDuplicateOffsetLastWins pins the duplicate-offset contract:
// when a level holds more than one element at the same offset, ComputeRoot uses
// the last one — matching the old map build's path[offset] = element semantics.
// (Path is exported and AddLeaf appends without deduplicating, so this shape is
// reachable.)
func TestComputeRootDuplicateOffsetLastWins(t *testing.T) {
	t.Parallel()

	isTxid := true
	leaf0 := benchTx(0).TxID()
	sibFirst := benchTx(1).TxID()
	sibLast := benchTx(2).TxID()
	require.False(t, sibFirst.Equal(*sibLast))

	// Level 0: the txid at offset 0 and two competing siblings at offset 1.
	mp := NewMerklePath(800000, [][]*PathElement{
		{
			{Offset: 0, Hash: leaf0, Txid: &isTxid},
			{Offset: 1, Hash: sibFirst},
			{Offset: 1, Hash: sibLast}, // duplicate offset 1 — last must win
		},
	})

	got, err := mp.ComputeRoot(leaf0)
	require.NoError(t, err)

	wantLastWins := MerkleTreeParent(leaf0, sibLast)
	firstWins := MerkleTreeParent(leaf0, sibFirst)
	require.True(t, got.Equal(*wantLastWins), "must combine with the last offset-1 element")
	require.False(t, got.Equal(*firstWins), "must not combine with the first offset-1 element")
}
