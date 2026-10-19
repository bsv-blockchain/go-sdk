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

// TestMerklePathCombineRejectsMergedRootMismatch pins the post-merge root
// check. Two paths can each compute the same root and still merge into a
// path whose root is different; Combine must refuse that and leave the
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
	require.ErrorContains(t, err, "does not match original root")
	require.ErrorContains(t, err, parent.String())
	require.Len(t, two.Path[0], 2)
	require.True(t, two.Path[0][0].Hash.Equal(*left))
	again, err := two.ComputeRoot(nil)
	require.NoError(t, err)
	require.True(t, again.Equal(*parent))

	// The opposite merge keeps the shared root, so it is accepted.
	err = lone.Combine(two)
	require.NoError(t, err)
	merged, err := lone.ComputeRoot(nil)
	require.NoError(t, err)
	require.True(t, merged.Equal(*parent))
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
