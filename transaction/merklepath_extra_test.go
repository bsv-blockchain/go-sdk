package transaction

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
)

func mpHashA(t *testing.T) *chainhash.Hash {
	t.Helper()
	h, err := chainhash.NewHashFromHex("1111111111111111111111111111111111111111111111111111111111111111")
	require.NoError(t, err)
	return h
}

func mpHashB(t *testing.T) *chainhash.Hash {
	t.Helper()
	h, err := chainhash.NewHashFromHex("2222222222222222222222222222222222222222222222222222222222222222")
	require.NoError(t, err)
	return h
}

// singleLeafPath builds a one-level, one-leaf MerklePath whose root equals the
// leaf hash.
func singleLeafPath(height uint32, hash *chainhash.Hash) *MerklePath {
	return &MerklePath{
		BlockHeight: height,
		Path:        [][]*PathElement{{{Offset: 0, Hash: hash}}},
	}
}

// brokenTwoLevelPath has a leaf at level 0 but an empty level 1, so ComputeRoot
// cannot find the sibling it needs.
func brokenTwoLevelPath(height uint32, hash *chainhash.Hash) *MerklePath {
	return &MerklePath{
		BlockHeight: height,
		Path:        [][]*PathElement{{{Offset: 0, Hash: hash}}, {}},
	}
}

func TestNewMerklePathFromReaderTruncated(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data []byte
	}{
		{name: "index-eof", data: nil},
		{name: "tree-height-eof", data: []byte{0x00}},
		{name: "leaf-count-overflow", data: []byte{0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		{name: "offset-eof", data: []byte{0x00, 0x01, 0x01, 0xFF, 0x00}},
		{name: "flags-eof", data: []byte{0x00, 0x01, 0x01, 0xFD, 0x00, 0x00}},
		{name: "hash-eof", data: []byte{0x00, 0x01, 0x01, 0x00, 0x00}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewMerklePathFromReader(bytes.NewReader(tc.data))
			require.Error(t, err)
		})
	}
}

func TestComputeRootHexInvalidTxid(t *testing.T) {
	t.Parallel()
	mp := singleLeafPath(100, mpHashA(t))
	bad := "not-hex"
	_, err := mp.ComputeRootHex(&bad)
	require.Error(t, err)
}

func TestComputeRootSingleLeaf(t *testing.T) {
	t.Parallel()
	a := mpHashA(t)
	mp := singleLeafPath(100, a)
	root, err := mp.ComputeRoot(nil)
	require.NoError(t, err)
	assert.True(t, root.Equal(*a))
}

func TestComputeRootMissingHash(t *testing.T) {
	t.Parallel()
	a := mpHashA(t)
	b := mpHashB(t)
	// Two leaves at level 0 and an empty level 1 forces the height-1 lookup to
	// recurse and fail, exercising GetOffsetLeaf's nil returns.
	mp := &MerklePath{
		BlockHeight: 100,
		Path: [][]*PathElement{
			{{Offset: 0, Hash: a}, {Offset: 1, Hash: b}},
			{},
		},
	}
	_, err := mp.ComputeRoot(a)
	require.Error(t, err)
}

func TestMerklePathCombineErrors(t *testing.T) {
	t.Parallel()
	a := mpHashA(t)
	b := mpHashB(t)

	t.Run("different-heights", func(t *testing.T) {
		t.Parallel()
		m := singleLeafPath(1, a)
		other := singleLeafPath(2, a)
		err := m.Combine(other)
		require.ErrorContains(t, err, "different block heights")
	})

	t.Run("root1-error", func(t *testing.T) {
		t.Parallel()
		m := brokenTwoLevelPath(5, a)
		other := singleLeafPath(5, a)
		err := m.Combine(other)
		require.Error(t, err)
	})

	t.Run("root2-error", func(t *testing.T) {
		t.Parallel()
		m := singleLeafPath(5, a)
		other := brokenTwoLevelPath(5, a)
		err := m.Combine(other)
		require.Error(t, err)
	})

	t.Run("different-roots", func(t *testing.T) {
		t.Parallel()
		m := singleLeafPath(5, a)
		other := singleLeafPath(5, b)
		err := m.Combine(other)
		require.ErrorContains(t, err, "different roots")
	})
}

// TestMerklePathCombineRejectsMergedRootMismatch pins the refusal to overwrite
// a node with different contents, even when both paths compute the same root.
// Either direction would replace offset 0; both must fail and leave the
// receiver unchanged.
func TestMerklePathCombineRejectsMergedRootMismatch(t *testing.T) {
	t.Parallel()
	left := mpHashA(t)
	right := mpHashB(t)
	parent := MerkleTreeParent(left, right)

	two := &MerklePath{
		BlockHeight: 10,
		Path: [][]*PathElement{{
			{Offset: 0, Hash: left},
			{Offset: 1, Hash: right},
		}},
	}
	root, err := two.ComputeRoot(nil)
	require.NoError(t, err)
	require.True(t, root.Equal(*parent))

	lone := singleLeafPath(10, parent)
	loneRoot, err := lone.ComputeRoot(nil)
	require.NoError(t, err)
	require.True(t, loneRoot.Equal(*parent))

	err = two.Combine(lone)
	require.ErrorContains(t, err, "conflicting nodes")
	require.Len(t, two.Path[0], 2)
	require.True(t, two.Path[0][0].Hash.Equal(*left))
	again, err := two.ComputeRoot(nil)
	require.NoError(t, err)
	require.True(t, again.Equal(*parent))

	err = lone.Combine(two)
	require.ErrorContains(t, err, "conflicting nodes")
	require.Len(t, lone.Path[0], 1)
	require.True(t, lone.Path[0][0].Hash.Equal(*parent))
	loneAgain, err := lone.ComputeRoot(nil)
	require.NoError(t, err)
	require.True(t, loneAgain.Equal(*parent))
}

func nthLeaf(t *testing.T, n byte) *chainhash.Hash {
	t.Helper()
	raw := make([]byte, 32)
	raw[31] = n
	h, err := chainhash.NewHash(raw)
	require.NoError(t, err)
	return h
}

// eightLeafProofs builds an 8-leaf tree and the sparse proofs of leaves 0 and 4.
// m proves leaf 4; other proves leaf 0. Both compute the same root.
func eightLeafProofs(t *testing.T) (leaves []*chainhash.Hash, root *chainhash.Hash, prove4, prove0 *MerklePath) {
	t.Helper()
	leaves = make([]*chainhash.Hash, 8)
	for i := range leaves {
		leaves[i] = nthLeaf(t, byte(i+1))
	}
	n01 := MerkleTreeParent(leaves[0], leaves[1])
	n23 := MerkleTreeParent(leaves[2], leaves[3])
	n45 := MerkleTreeParent(leaves[4], leaves[5])
	n67 := MerkleTreeParent(leaves[6], leaves[7])
	n03 := MerkleTreeParent(n01, n23)
	n47 := MerkleTreeParent(n45, n67)
	root = MerkleTreeParent(n03, n47)
	txid := true
	prove4 = &MerklePath{
		BlockHeight: 900,
		Path: [][]*PathElement{
			{{Offset: 4, Hash: leaves[4], Txid: &txid}, {Offset: 5, Hash: leaves[5]}},
			{{Offset: 3, Hash: n67}},
			{{Offset: 0, Hash: n03}},
		},
	}
	prove0 = &MerklePath{
		BlockHeight: 900,
		Path: [][]*PathElement{
			{{Offset: 0, Hash: leaves[0], Txid: &txid}, {Offset: 1, Hash: leaves[1]}},
			{{Offset: 1, Hash: n23}},
			{{Offset: 1, Hash: n47}},
		},
	}
	return leaves, root, prove4, prove0
}

// TestMerklePathCombineRejectsReviewOverwrites covers the two Combine bypasses
// from the #378 review: an extra sibling hash that leaves the first-leaf climb
// alone, and garbage leaves that cause a real parent to be dropped.
func TestMerklePathCombineRejectsReviewOverwrites(t *testing.T) {
	t.Parallel()
	leaves, root, prove4, prove0 := eightLeafProofs(t)

	got, err := prove4.ComputeRoot(leaves[4])
	require.NoError(t, err)
	require.True(t, got.Equal(*root))
	got, err = prove0.ComputeRoot(leaves[0])
	require.NoError(t, err)
	require.True(t, got.Equal(*root))

	t.Run("honest proofs merge", func(t *testing.T) {
		t.Parallel()
		_, root, m, other := eightLeafProofs(t)
		require.NoError(t, m.Combine(other))
		for _, txid := range []*chainhash.Hash{m.Path[0][0].Hash, leaves[4], leaves[0]} {
			got, err := m.ComputeRoot(txid)
			require.NoError(t, err)
			require.True(t, got.Equal(*root))
		}
	})

	t.Run("extra sibling hash", func(t *testing.T) {
		t.Parallel()
		leaves, root, m, other := eightLeafProofs(t)
		other.Path[0] = append(other.Path[0], &PathElement{Offset: 5, Hash: nthLeaf(t, 99)})
		err := m.Combine(other)
		require.ErrorContains(t, err, "conflicting nodes")
		got, err := m.ComputeRoot(leaves[4])
		require.NoError(t, err)
		require.True(t, got.Equal(*root))
		require.True(t, m.Path[0][1].Hash.Equal(*leaves[5]))
	})

	t.Run("garbage leaves drop a real parent", func(t *testing.T) {
		t.Parallel()
		leaves, root, m, other := eightLeafProofs(t)
		parent := m.Path[1][0].Hash
		other.Path[0] = append(other.Path[0],
			&PathElement{Offset: 6, Hash: nthLeaf(t, 100)},
			&PathElement{Offset: 7, Hash: nthLeaf(t, 101)},
		)
		err := m.Combine(other)
		require.ErrorContains(t, err, "does not match its children")
		got, err := m.ComputeRoot(leaves[4])
		require.NoError(t, err)
		require.True(t, got.Equal(*root))
		require.True(t, m.Path[1][0].Hash.Equal(*parent))
	})
}

func TestMerklePathVerifyComputeRootError(t *testing.T) {
	t.Parallel()
	a := mpHashA(t)
	b := mpHashB(t)
	// Two leaves so ComputeRoot must actually search for the txid, which is
	// absent -> error.
	mp := &MerklePath{
		BlockHeight: 100,
		Path:        [][]*PathElement{{{Offset: 0, Hash: a}, {Offset: 1, Hash: b}}},
	}
	wrong, err := chainhash.NewHashFromHex("3333333333333333333333333333333333333333333333333333333333333333")
	require.NoError(t, err)

	ok, err := mp.Verify(context.Background(), wrong, &mockChainTracker{validResult: true})
	require.Error(t, err)
	assert.False(t, ok)
}

func TestFindLeafByOffsetOutOfRange(t *testing.T) {
	t.Parallel()
	mp := singleLeafPath(1, mpHashA(t))
	assert.Nil(t, mp.FindLeafByOffset(-1, 0))
	assert.Nil(t, mp.FindLeafByOffset(5, 0))
}

func TestComputeMissingHashesTooFewLevels(t *testing.T) {
	t.Parallel()
	mp := singleLeafPath(1, mpHashA(t))
	// Single-level paths return early without modification.
	mp.ComputeMissingHashes()
	assert.Len(t, mp.Path, 1)
}

func TestMerkleTreeParentStrErrors(t *testing.T) {
	t.Parallel()

	_, err := MerkleTreeParentStr("zz", "00")
	require.Error(t, err)

	_, err = MerkleTreeParentStr("00", "zz")
	require.Error(t, err)
}
