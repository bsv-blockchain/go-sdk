// Package merklepath_test runs the ts-stack conformance vectors for
// sdk/transactions/merkle-path.json against the go-sdk MerklePath (BUMP)
// implementation, mirroring the assertions made by the TS reference runner
// (conformance/runner/ts/dispatchers/{sdk.ts,sdkHelpers.ts} in ts-stack).
package merklepath_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	primitives "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// mpInput is a superset decode target covering every shape used by
// sdk/transactions/merkle-path.json's vectors.
type mpInput struct {
	BumpHex         string   `json:"bump_hex"`
	CombinedBumpHex string   `json:"combined_bump_hex"`
	Txid            string   `json:"txid"`
	BlockHeight     uint32   `json:"block_height"`
	Height          *uint32  `json:"height"`
	Txids           []string `json:"txids"`
	FullBlockTxids  []string `json:"full_block_txids"`
	TxidsAtLevel0   []string `json:"txids_at_level_0"`
	Leaf0Hash       string   `json:"leaf0_hash"`
	Leaf1Hash       string   `json:"leaf1_hash"`
	Leaf1Duplicate  bool     `json:"leaf1_duplicate"`
	TxidTx2         string   `json:"txid_tx2"`
	TxidTx5         string   `json:"txid_tx5"`
	TxidTx8         string   `json:"txid_tx8"`
	ExtractTxid     string   `json:"extract_txid"`
	TxidsToExtract  []string `json:"txids_to_extract"`
}

// mpExpected is a superset decode target covering every expectation shape.
type mpExpected struct {
	BlockHeight              *uint32 `json:"block_height"`
	PathLevels               *int    `json:"path_levels"`
	PathLevel0Length         *int    `json:"path_level0_length"`
	ToHex                    string  `json:"toHex"`
	MerkleRoot               string  `json:"merkle_root"`
	SerializedBumpHex        string  `json:"serialized_bump_hex"`
	BumpHex                  string  `json:"bump_hex"`
	ComputedHash             string  `json:"computed_hash"`
	MerkleRootForTx0         string  `json:"merkle_root_for_tx0"`
	MerkleRootForTx1         string  `json:"merkle_root_for_tx1"`
	MerkleRootForTx2         string  `json:"merkle_root_for_tx2"`
	MerkleRootForTx3         string  `json:"merkle_root_for_tx3"`
	Throws                   bool    `json:"throws"`
	ExtractedSmallerThanFull bool    `json:"extracted_smaller_than_full"`
}

// block125632Txids are the 11 transaction ids of block 125632 (display/txid
// order), shared by mp-block125632-001/002/003. mp-block125632-002 and -003
// only give a partial sibling proof (not enough to rebuild a compact BUMP
// without the full leaf set), and the TS reference runner itself performs no
// assertion for either vector (dispatchMerklePathWithoutBump falls through
// every branch: the vectors key on "txid", not "txids"/"full_block_txids").
// We go further than that vacuous parity and confirm each proof's subject
// txid is actually a member of the block whose merkle root the vector
// asserts, recomputing the root from the full leaf set.
var block125632Txids = []string{
	"17cba98da71fe75862aac894392f2ff604356db386767fec364877a5a9ff200c",
	"14ce64bd223ec9bb42662b74fdcf94f96a209a1aee72b7ba7639db503150ec2e",
	"90a2de85351cfadd2326b9b0098e9c453af09b2980835f57a1429bbb44beb872",
	"a31f2ddfea7ddd4581dca3007ee99e58ea6baa97a8ac3b32bb4610baac9f7206",
	"c36eeed6fbc0259d30804f59f804dfcda35a54461157d6ac9c094f0ea378f35c",
	"17752483868c52a98407a0e226d73b42e214e0fad548541619d858e1fd4a9549",
	"3b8c4460412cfc55be0d50308ba704a859bd6f83bfed01b0828c9b067cd69246",
	"a3f1b9d4b3ef3b061af352fdc2d02048417030fef9282c36da689cd899437cdb",
	"66e2b022da877621ef197e02c3ef7d3f820d33a86ead2e72bf966432ea6776f1",
	"e988b5d7a2cec8e0759ade2e151737d1cdfdde68accff42938583ad12eb98b99",
	"5e7a8a8ec3f912ac1c4e90279c04263f170ed055c0411c8d490b846f01e6a99e",
}

// computeMerkleRootFromDisplayTxids mirrors ts-stack's
// computeMerkleRootFromDisplayTxids (conformance/runner/ts/dispatchers/sdkHelpers.ts):
// txids are given in display order, reversed to internal order, paired up
// (duplicating the last leaf of an odd level), hashed with sha256d, and the
// final root is reversed back to display order.
func computeMerkleRootFromDisplayTxids(t *testing.T, txids []string) string {
	t.Helper()
	require.NotEmpty(t, txids)

	level := make([][]byte, len(txids))
	for i, txidHex := range txids {
		b, err := hex.DecodeString(txidHex)
		require.NoError(t, err)
		level[i] = reverseBytes(b)
	}

	for len(level) > 1 {
		if len(level)%2 != 0 {
			level = append(level, level[len(level)-1]) //nolint:makezero // duplicating the odd level's last leaf is deliberate (Bitcoin's odd-node rule), not an accidental append to a fixed-size slice
		}
		next := make([][]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			concat := make([]byte, 0, len(level[i])+len(level[i+1]))
			concat = append(concat, level[i]...)
			concat = append(concat, level[i+1]...)
			next = append(next, primitives.Sha256d(concat))
		}
		level = next
	}

	return hex.EncodeToString(reverseBytes(level[0]))
}

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[len(b)-1-i] = v
	}
	return out
}

func mustHash(t *testing.T, hexStr string) *chainhash.Hash {
	t.Helper()
	h, err := chainhash.NewHashFromHex(hexStr)
	require.NoError(t, err)
	return h
}

// buildFullBlockMerklePath builds a level-0-only compound MerklePath (every
// display-order txid, in order, each flagged Txid=true), the shape a real
// full-block BUMP built from scratch takes before any pruning.
func buildFullBlockMerklePath(t *testing.T, blockHeight uint32, txids []string) *transaction.MerklePath {
	t.Helper()
	level0 := make([]*transaction.PathElement, len(txids))
	txidFlag := true
	for i, txidHex := range txids {
		level0[i] = &transaction.PathElement{
			Offset: uint64(i),
			Hash:   mustHash(t, txidHex),
			Txid:   &txidFlag,
		}
	}
	return transaction.NewMerklePath(blockHeight, [][]*transaction.PathElement{level0})
}

// countPathLeaves returns the total number of PathElements across every
// level of a MerklePath, used to confirm an extracted proof is genuinely
// smaller than the path it was extracted from.
func countPathLeaves(mp *transaction.MerklePath) int {
	total := 0
	for _, level := range mp.Path {
		total += len(level)
	}
	return total
}

func TestMerklePathConformance(t *testing.T) {
	file := conformance.Load(t, "sdk/transactions/merkle-path.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in mpInput
		v.DecodeInput(t, &in)
		var exp mpExpected
		v.DecodeExpected(t, &exp)

		switch v.ID {
		case "mp-parse-001":
			mp, err := transaction.NewMerklePathFromHex(in.BumpHex)
			require.NoError(t, err)
			require.Equal(t, *exp.BlockHeight, mp.BlockHeight)
			require.Len(t, mp.Path, *exp.PathLevels)
			require.Len(t, mp.Path[0], *exp.PathLevel0Length)

		case "mp-serialize-001":
			mp, err := transaction.NewMerklePathFromHex(in.BumpHex)
			require.NoError(t, err)
			require.Equal(t, exp.ToHex, mp.Hex())

		case "mp-computeroot-001", "mp-computeroot-002", "mp-computeroot-003", "mp-single-tx-001":
			mp, err := transaction.NewMerklePathFromHex(in.BumpHex)
			require.NoError(t, err)
			root, err := mp.ComputeRoot(mustHash(t, in.Txid))
			require.NoError(t, err)
			require.Equal(t, exp.MerkleRoot, root.String())
			if exp.BlockHeight != nil {
				require.Equal(t, *exp.BlockHeight, mp.BlockHeight)
			}

		case "mp-compound-001":
			mp, err := transaction.NewMerklePathFromHex(in.BumpHex)
			require.NoError(t, err)
			require.Equal(t, exp.SerializedBumpHex, mp.Hex())
			roots := []string{exp.MerkleRootForTx0, exp.MerkleRootForTx1, exp.MerkleRootForTx2, exp.MerkleRootForTx3}
			for i, txid := range in.TxidsAtLevel0 {
				want := roots[i]
				if want == "" {
					want = exp.MerkleRootForTx0
				}
				root, err := mp.ComputeRoot(mustHash(t, txid))
				require.NoError(t, err)
				require.Equalf(t, want, root.String(), "txid index %d", i)
			}

		case "mp-coinbase-001":
			mp, err := transaction.NewMerklePathFromCoinbaseTxid(mustHash(t, in.Txid), *in.Height)
			require.NoError(t, err)
			require.Equal(t, exp.BumpHex, mp.Hex())
			require.Equal(t, *exp.BlockHeight, mp.BlockHeight)
			root, err := mp.ComputeRoot(mustHash(t, in.Txid))
			require.NoError(t, err)
			require.Equal(t, exp.MerkleRoot, root.String())

		case "mp-block125632-001":
			require.Equal(t, block125632Txids, in.Txids, "vector's embedded txid list drifted from the shared fixture")
			require.Equal(t, exp.MerkleRoot, computeMerkleRootFromDisplayTxids(t, in.Txids))

		case "mp-block125632-002", "mp-block125632-003":
			require.Contains(t, block125632Txids, in.Txid, "proof subject must be a member of block 125632")
			require.Equal(t, exp.MerkleRoot, computeMerkleRootFromDisplayTxids(t, block125632Txids))

		case "mp-combine-001":
			mp, err := transaction.NewMerklePathFromHex(in.CombinedBumpHex)
			require.NoError(t, err)
			require.Equal(t, exp.SerializedBumpHex, mp.Hex())
			for _, txid := range []string{in.TxidTx2, in.TxidTx5, in.TxidTx8} {
				root, err := mp.ComputeRoot(mustHash(t, txid))
				require.NoError(t, err)
				require.Equal(t, exp.MerkleRoot, root.String())
			}

		case "mp-findleaf-001":
			// leaf1.duplicate=true must override a populated leaf1.hash: the
			// synthesized sibling is leaf0 doubled, exactly as
			// MerklePath.ComputeRoot treats a Duplicate leaf regardless of
			// whether a Hash value also happens to be present (merklepath.go
			// ComputeRoot's `if leaf.Duplicate != nil && *leaf.Duplicate`
			// branch never even reads leaf.Hash).
			dup := in.Leaf1Duplicate
			leaf0 := mustHash(t, in.Leaf0Hash)
			leaf1 := mustHash(t, in.Leaf1Hash)
			mp := transaction.NewMerklePath(in.BlockHeight, [][]*transaction.PathElement{{
				{Offset: 0, Hash: leaf0},
				{Offset: 1, Hash: leaf1, Duplicate: &dup},
			}})
			root, err := mp.ComputeRoot(leaf0)
			require.NoError(t, err)
			require.Equal(t, exp.ComputedHash, root.String())

		case "mp-extract-001":
			// The TS reference runner's dispatchMerklePathWithoutBump checks
			// 'full_block_txids' before 'txids_to_extract', so it never
			// actually calls MerklePath.extract() for this vector either
			// (it only recomputes the root from the full leaf list and, for
			// extracted_smaller_than_full, tautologically checks
			// txids.length >= 2). Since this task explicitly asks for a real,
			// additive MerklePath.Extract mirroring ts-sdk's extract(), this
			// test goes further and exercises it directly: build the full
			// compound path, confirm its root matches, extract a minimal
			// proof for extract_txid, confirm the extracted proof still
			// proves the same root, and confirm it is smaller than the full
			// block's leaf set.
			require.Equal(t, block125632Txids, in.FullBlockTxids, "vector's embedded txid list drifted from the shared fixture")
			require.Equal(t, exp.MerkleRoot, computeMerkleRootFromDisplayTxids(t, in.FullBlockTxids))

			fullPath := buildFullBlockMerklePath(t, in.BlockHeight, in.FullBlockTxids)
			fullRoot, err := fullPath.ComputeRoot(nil)
			require.NoError(t, err)
			require.Equal(t, exp.MerkleRoot, fullRoot.String())

			extractTxid := mustHash(t, in.ExtractTxid)
			extracted, err := fullPath.Extract([]*chainhash.Hash{extractTxid})
			require.NoError(t, err)
			extractedRoot, err := extracted.ComputeRoot(extractTxid)
			require.NoError(t, err)
			require.Equal(t, exp.MerkleRoot, extractedRoot.String())
			if exp.ExtractedSmallerThanFull {
				require.Less(t, countPathLeaves(extracted), countPathLeaves(fullPath),
					"extracted proof must be smaller than the full block path")
			}

		case "mp-extract-002":
			require.Empty(t, in.TxidsToExtract)
			// No real merkle data is given for this vector (it only pins the
			// empty-input error case), so exercise Extract's own argument
			// validation against a minimal, otherwise-valid path.
			mp, err := transaction.NewMerklePathFromCoinbaseTxid(mustHash(t, block125632Txids[0]), in.BlockHeight)
			require.NoError(t, err)
			_, err = mp.Extract(nil)
			require.Error(t, err)
			require.Contains(t, strings.ToLower(err.Error()), "at least one txid must be provided")

		case "mp-extract-003":
			fullPath := buildFullBlockMerklePath(t, 125632, block125632Txids)
			_, err := fullPath.Extract([]*chainhash.Hash{mustHash(t, in.Txid)})
			require.Error(t, err)

		default:
			t.Fatalf("unhandled vector id %q", v.ID)
		}
	})
}
