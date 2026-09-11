package transaction

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/util"
)

// MerkleTreeParentStr returns the Merkle Tree parent of two MerkleTree children using hex strings instead of bytes.
func MerkleTreeParentStr(leftNode, rightNode string) (string, error) {
	l, err := hex.DecodeString(leftNode)
	if err != nil {
		return "", err
	}
	r, err := hex.DecodeString(rightNode)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(MerkleTreeParentBytes(l, r)), nil
}

// MerkleTreeParentBytes returns the Merkle Tree parent of two MerkleTree children.
func MerkleTreeParentBytes(leftNode, rightNode []byte) []byte {
	concatenated := flipTwoArrays(leftNode, rightNode)

	hash := crypto.Sha256d(concatenated)

	util.ReverseBytesInPlace(hash)

	return hash
}

// flipTwoArrays reverses two byte arrays individually and returns as one concatenated slice
// example:
// for a=[a, b, c], b=[d, e, f] the result is [c, b, a, f, e, d]
func flipTwoArrays(a, b []byte) []byte {
	result := make([]byte, 0, len(a)+len(b))
	for i := len(a) - 1; i >= 0; i-- {
		result = append(result, a[i])
	}
	for i := len(b) - 1; i >= 0; i-- {
		result = append(result, b[i])
	}
	return result
}

// MerkleTreeParent returns the Merkle Tree parent of two Merkle Tree children.
// The expectation is that the bytes are not reversed.
func MerkleTreeParent(l, r *chainhash.Hash) *chainhash.Hash {
	// Double-SHA256 of l||r using a stack buffer, avoiding the per-call
	// concatenation and intermediate hash allocations. Byte-identical to
	// chainhash.NewHash(crypto.Sha256d(l||r)).
	var buf [chainhash.HashSize * 2]byte
	copy(buf[:chainhash.HashSize], l[:])
	copy(buf[chainhash.HashSize:], r[:])
	first := sha256.Sum256(buf[:])
	parent := chainhash.Hash(sha256.Sum256(first[:]))
	return &parent
}
