package transaction

import (
	"fmt"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/stretchr/testify/require"
)

// TestMerkleTreeParentByteIdentity locks the optimized MerkleTreeParent to the
// reference double-SHA256 of l||r (unreversed).
func TestMerkleTreeParentByteIdentity(t *testing.T) {
	mk := func(seed byte) *chainhash.Hash {
		var h chainhash.Hash
		for i := range h {
			h[i] = seed + byte(i&0xff)
		}
		return &h
	}
	for _, seeds := range [][2]byte{{1, 2}, {0, 0}, {0xFF, 0x7F}} {
		l, r := mk(seeds[0]), mk(seeds[1])
		concat := append(append([]byte{}, l[:]...), r[:]...)
		want, err := chainhash.NewHash(crypto.Sha256d(concat))
		require.NoError(t, err)
		require.Equal(t, *want, *MerkleTreeParent(l, r), "seeds %v", seeds)
	}
}

func merkleBenchLeaves(n int) []*chainhash.Hash {
	leaves := make([]*chainhash.Hash, n)
	for i := range leaves {
		var h chainhash.Hash
		h[0] = byte(i & 0xff)
		h[1] = byte((i >> 8) & 0xff)
		leaves[i] = &h
	}
	return leaves
}

// BenchmarkMerklePathBytes measures BUMP serialization; the pre-sized buffer +
// Hash[:] make it a single allocation regardless of leaf count.
func BenchmarkMerklePathBytes(b *testing.B) {
	for _, n := range []int{16, 256} {
		mp := benchFullBUMP(800000, benchMerkleTree(merkleBenchLeaves(n)))
		b.Run(fmt.Sprintf("leaves=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = mp.Bytes()
			}
		})
	}
}

// BenchmarkMerkleTreeParent measures a single parent-hash computation.
func BenchmarkMerkleTreeParent(b *testing.B) {
	leaves := merkleBenchLeaves(2)
	l, r := leaves[0], leaves[1]
	b.ReportAllocs()
	for b.Loop() {
		_ = MerkleTreeParent(l, r)
	}
}
