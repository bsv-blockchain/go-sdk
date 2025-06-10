package transaction

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"sort"

	"github.com/bsv-blockchain/go-sdk/v2/chainhash"
	"github.com/bsv-blockchain/go-sdk/v2/transaction/chaintracker"
	"github.com/bsv-blockchain/go-sdk/v2/util"
	"github.com/pkg/errors"
)

type PathElement struct {
	Offset    uint64          `json:"offset"`
	Hash      *chainhash.Hash `json:"hash,omitempty"`
	Txid      *bool           `json:"txid,omitempty"`
	Duplicate *bool           `json:"duplicate,omitempty"`
}

type MerklePath struct {
	BlockHeight uint32           `json:"blockHeight"`
	Path        [][]*PathElement `json:"path"`
}

type IndexedPath []map[uint64]*PathElement

func (ip IndexedPath) GetOffsetLeaf(layer int, offset uint64) *PathElement {
	if leaf, ok := ip[layer][offset]; ok {
		return leaf
	}
	if layer == 0 {
		return nil
	}

	prevOffset := offset * 2
	left := ip.GetOffsetLeaf(layer-1, prevOffset)
	right := ip.GetOffsetLeaf(layer-1, prevOffset+1)
	if left != nil && right != nil {
		pathElement := &PathElement{
			Offset: offset,
		}
		if right.Duplicate != nil && *right.Duplicate {
			pathElement.Hash = MerkleTreeParent(left.Hash, left.Hash)
		} else {
			pathElement.Hash = MerkleTreeParent(left.Hash, right.Hash)
		}
		return pathElement
	}
	return nil
}

// NewMerklePath creates a new MerklePath with the given block height and path
func NewMerklePath(blockHeight uint32, path [][]*PathElement) *MerklePath {
	return &MerklePath{
		BlockHeight: blockHeight,
		Path:        path,
	}
}

// NewMerklePathFromHex creates a new MerklePath with the given hex data
func NewMerklePathFromHex(hexData string) (*MerklePath, error) {
	bin, err := hex.DecodeString(hexData)
	if err != nil {
		return nil, err
	}
	return NewMerklePathFromBinary(bin)
}

// NewMerklePathFromBinary creates a new MerklePath with the given binary
func NewMerklePathFromBinary(b []byte) (*MerklePath, error) {
	if len(b) < 37 {
		return nil, errors.New("BUMP bytes do not contain enough data to be valid")
	}
	return NewMerklePathFromReader(bytes.NewReader(b))
}

func NewMerklePathFromReader(reader io.Reader) (*MerklePath, error) {
	bump := &MerklePath{}

	var index util.VarInt
	_, err := index.ReadFrom(reader)
	if err != nil {
		return nil, err
	}
	// index, size := NewVarIntFromBytes(bytes[skip:])
	// skip += size
	bump.BlockHeight = uint32(index)

	var treeHeight uint8
	err = binary.Read(reader, binary.LittleEndian, &treeHeight)
	if err != nil {
		return nil, err
	}

	// We expect tree height levels.
	bump.Path = make([][]*PathElement, treeHeight)

	for lv := uint8(0); lv < treeHeight; lv++ {
		var nLeavesAtThisHeight util.VarInt
		_, err = nLeavesAtThisHeight.ReadFrom(reader)
		if err != nil {
			return nil, err
		}

		bump.Path[lv] = make([]*PathElement, nLeavesAtThisHeight)
		for lf := uint64(0); lf < uint64(nLeavesAtThisHeight); lf++ {
			// For each leaf we parse the offset, hash, txid and duplicate.
			var offset util.VarInt
			_, err = offset.ReadFrom(reader)
			if err != nil {
				return nil, err
			}
			var l PathElement
			o := uint64(offset)
			l.Offset = o

			var flags byte
			err = binary.Read(reader, binary.LittleEndian, &flags)
			if err != nil {
				return nil, err
			}

			dup := flags&1 > 0
			txid := flags&2 > 0
			if dup {
				l.Duplicate = &dup
			} else {
				hash := make([]byte, 32)
				if _, err = reader.Read(hash); err != nil {
					return nil, err
				} else if l.Hash, err = chainhash.NewHash(hash); err != nil {
					return nil, err
				}
			}
			if txid {
				l.Txid = &txid
			}
			bump.Path[lv][lf] = &l
		}
	}

	// Sort each of the levels by the offset for consistency.
	for _, level := range bump.Path {
		sort.Slice(level, func(i, j int) bool {
			return level[i].Offset < level[j].Offset
		})
	}

	return bump, nil
}

// Bytes encodes a BUMP as a slice of bytes. BUMP Binary Format according to BRC-74 https://brc.dev/74
func (mp *MerklePath) Bytes() []byte {
	bytes := util.VarInt(mp.BlockHeight).Bytes()
	treeHeight := len(mp.Path)
	bytes = append(bytes, byte(treeHeight))
	for level := 0; level < treeHeight; level++ {
		nLeaves := len(mp.Path[level])
		bytes = append(bytes, util.VarInt(nLeaves).Bytes()...)
		for _, leaf := range mp.Path[level] {
			bytes = append(bytes, util.VarInt(leaf.Offset).Bytes()...)
			flags := byte(0)
			if leaf.Duplicate != nil && *leaf.Duplicate {
				flags |= 1
			}
			if leaf.Txid != nil && *leaf.Txid {
				flags |= 2
			}
			bytes = append(bytes, flags)
			if (flags & 1) == 0 {
				bytes = append(bytes, leaf.Hash.CloneBytes()...)
			}
		}
	}
	return bytes
}

// Hex converts the MerklePath to a hexadecimal string representation
func (mp *MerklePath) Hex() string {
	return hex.EncodeToString(mp.Bytes())
}

func (mp *MerklePath) ComputeRootHex(txidStr *string) (string, error) {
	var txid *chainhash.Hash
	if txidStr != nil {
		var err error
		if txid, err = chainhash.NewHashFromHex(*txidStr); err != nil {
			return "", err
		}
	}
	if root, err := mp.ComputeRoot(txid); err != nil {
		return "", err
	} else {
		return root.String(), nil
	}
}

// ComputeRoot computes the Merkle root from a given transaction ID
func (mp *MerklePath) ComputeRoot(txid *chainhash.Hash) (*chainhash.Hash, error) {
	if txid == nil {
		for _, l := range mp.Path[0] {
			if l.Hash != nil {
				txid = l.Hash
				break
			}
		}
	}
	if len(mp.Path) == 1 {
		// if there is only one txid in the block then the root is the txid.
		if len(mp.Path[0]) == 1 {
			return txid, nil
		}
	}
	indexedPath := make(IndexedPath, len(mp.Path))
	for h := 0; h < len(mp.Path); h++ {
		path := map[uint64]*PathElement{}
		for l := 0; l < len(mp.Path[h]); l++ {
			path[mp.Path[h][l].Offset] = mp.Path[h][l]
		}
		indexedPath[h] = path
	}

	// Find the index of the txid at the lowest level of the Merkle tree
	var txLeaf *PathElement
	for _, l := range mp.Path[0] {
		if l.Hash != nil && l.Hash.Equal(*txid) {
			txLeaf = l
			break
		}
	}
	if txLeaf == nil {
		return nil, fmt.Errorf("the BUMP does not contain the txid: %s", *txid)
	}

	// Calculate the root using the index as a way to determine which direction to concatenate.
	workingHash := txLeaf.Hash
	index := txLeaf.Offset

	for height := range mp.Path {
		offset := (index >> height) ^ 1
		leaf := indexedPath.GetOffsetLeaf(height, offset)
		if leaf == nil {
			return nil, fmt.Errorf("we do not have a hash for this index at height: %v", height)
		}
		if leaf.Duplicate != nil && *leaf.Duplicate {
			workingHash = MerkleTreeParent(workingHash, workingHash)
		} else {
			leafBytes := leaf.Hash
			if (offset % 2) != 0 {
				workingHash = MerkleTreeParent(workingHash, leafBytes)
			} else {
				workingHash = MerkleTreeParent(leafBytes, workingHash)
			}
		}
	}
	return workingHash, nil
}

// Verify checks if a given transaction ID is part of the Merkle tree
// at the specified block height using a chain tracker
func (mp *MerklePath) VerifyHex(txidStr string, ct chaintracker.ChainTracker) (bool, error) {
	if txid, err := chainhash.NewHashFromHex(txidStr); err != nil {
		return false, err
	} else {
		return mp.Verify(txid, ct)
	}
}

func (mp *MerklePath) Verify(txid *chainhash.Hash, ct chaintracker.ChainTracker) (bool, error) {
	root, err := mp.ComputeRoot(txid)
	if err != nil {
		return false, err
	}
	return ct.IsValidRootForHeight(root, mp.BlockHeight)
}

func (m *MerklePath) Combine(other *MerklePath) (err error) {
	if m.BlockHeight != other.BlockHeight {
		return errors.New("cannot combine MerklePaths with different block heights")
	}

	root1, err := m.ComputeRootHex(nil)
	if err != nil {
		return err
	}
	root2, err := other.ComputeRootHex(nil)
	if err != nil {
		return err
	}

	if root1 != root2 {
		return errors.New("cannot combine MerklePaths with different roots")
	}

	combinedPath := make([]map[uint64]*PathElement, len(m.Path))
	for h := 0; h < len(m.Path); h++ {
		path := map[uint64]*PathElement{}
		for l := 0; l < len(m.Path[h]); l++ {
			path[m.Path[h][l].Offset] = m.Path[h][l]
		}
		combinedPath[h] = path
	}

	for h := 0; h < len(other.Path); h++ {
		for l := 0; l < len(other.Path[h]); l++ {
			combinedPath[h][other.Path[h][l].Offset] = other.Path[h][l]
		}
	}

	m.Path = make([][]*PathElement, len(combinedPath))
	for h := len(m.Path) - 1; h >= 0; h-- {
		m.Path[h] = make([]*PathElement, 0, len(combinedPath[h]))
		for offset := range combinedPath[h] {
			if h > 0 {
				childOffset := offset * 2
				_, hasLeft := combinedPath[h-1][childOffset]
				_, hasRight := combinedPath[h-1][childOffset+1]
				if hasLeft && hasRight {
					continue
				}
			}
			m.Path[h] = append(m.Path[h], combinedPath[h][offset])
		}
		slices.SortFunc(m.Path[h], func(a, b *PathElement) int {
			return int(a.Offset) - int(b.Offset)
		})
	}

	return
}
