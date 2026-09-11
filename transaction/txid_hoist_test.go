package transaction

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
)

// leafPathContaining builds a single-level merkle path whose Path[0] has n
// leaves, the last of which is target. AddMerkleProof scans Path[0] for the
// transaction's txid, so putting the match at the end forces a full scan.
func leafPathContaining(n int, target *chainhash.Hash) *MerklePath {
	leaves := make([]*PathElement, n)
	for i := range n {
		h := new(chainhash.Hash)
		h[0] = byte(i & 0xff)
		h[1] = byte((i >> 8) & 0xff)
		leaves[i] = &PathElement{Offset: uint64(i), Hash: h}
	}
	isTxid := true
	leaves[n-1].Hash = target
	leaves[n-1].Txid = &isTxid
	return &MerklePath{BlockHeight: 800000, Path: [][]*PathElement{leaves}}
}

// TestAddMerkleProofScansLeafLevel locks that AddMerkleProof finds the
// transaction's txid anywhere in a large leaf level and rejects a level that
// does not contain it. This guards the hoisted single-txid scan.
func TestAddMerkleProofScansLeafLevel(t *testing.T) {
	tx := benchTx(1)
	txid := tx.TxID()

	require.NoError(t, tx.AddMerkleProof(leafPathContaining(64, txid)))
	require.NotNil(t, tx.MerklePath)

	var absent chainhash.Hash
	absent[0], absent[31] = 0xFF, 0xFF
	tx.MerklePath = nil
	require.ErrorIs(t, tx.AddMerkleProof(leafPathContaining(64, &absent)), ErrBadMerkleProof)
	require.Nil(t, tx.MerklePath)
}

// BenchmarkAddMerkleProof measures attaching a whole-block merkle proof whose
// leaf level is scanned for the transaction's txid. With the txid hoisted out
// of the scan predicate this is one TxID computation regardless of leaf count.
func BenchmarkAddMerkleProof(b *testing.B) {
	for _, n := range []int{16, 256, 1024} {
		b.Run(fmt.Sprintf("leaves=%d", n), func(b *testing.B) {
			tx := benchTx(1)
			bump := leafPathContaining(n, tx.TxID())
			b.ReportAllocs()
			for b.Loop() {
				tx.MerklePath = nil
				if err := tx.AddMerkleProof(bump); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
