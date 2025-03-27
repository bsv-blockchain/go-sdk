package transaction_test

import (
	"encoding/hex"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/stretchr/testify/require"
)

func TestGetMerkleTreeParentStr(t *testing.T) {
	leftNode := "d6c79a6ef05572f0cb8e9a450c561fc40b0a8a7d48faad95e20d93ddeb08c231"
	rightNode := "b1ed931b79056438b990d8981ba46fae97e5574b142445a74a44b978af284f98"

	expected := "b0d537b3ee52e472507f453df3d69561720346118a5a8c4d85ca0de73bc792be"

	parent, err := transaction.MerkleTreeParentStr(leftNode, rightNode)

	require.NoError(t, err)
	require.Equal(t, expected, parent)
}

func TestGetMerkleTreeParent(t *testing.T) {
	leftNode, _ := hex.DecodeString("d6c79a6ef05572f0cb8e9a450c561fc40b0a8a7d48faad95e20d93ddeb08c231")
	rightNode, _ := hex.DecodeString("b1ed931b79056438b990d8981ba46fae97e5574b142445a74a44b978af284f98")

	expected, _ := hex.DecodeString("b0d537b3ee52e472507f453df3d69561720346118a5a8c4d85ca0de73bc792be")

	parent := transaction.MerkleTreeParentBytes(leftNode, rightNode)

	require.Equal(t, expected, parent)
}
