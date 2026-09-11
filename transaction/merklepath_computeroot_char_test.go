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
	}
}
