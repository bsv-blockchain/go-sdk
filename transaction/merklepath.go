package transaction

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/bits"
	"slices"
	"sort"

	"github.com/pkg/errors"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
	"github.com/bsv-blockchain/go-sdk/util"
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
	// Guard: layer may exceed stored levels for single-level compound paths
	if layer < len(ip) {
		if leaf, ok := ip[layer][offset]; ok {
			return leaf
		}
	}
	if layer == 0 {
		return nil
	}

	prevOffset := offset * 2
	left := ip.GetOffsetLeaf(layer-1, prevOffset)
	if left == nil || left.Hash == nil {
		return nil
	}
	right := ip.GetOffsetLeaf(layer-1, prevOffset+1)
	if right == nil || right.Hash == nil {
		if right != nil && right.Duplicate != nil && *right.Duplicate {
			return &PathElement{Offset: offset, Hash: MerkleTreeParent(left.Hash, left.Hash)}
		}
		// A single-level compound path (e.g. a full block's worth of level-0
		// txids with no precomputed internal levels) may have an odd node
		// count at some ancestor height with no explicit duplicate marker at
		// all: prevOffset is then the last (unpaired) node at that height,
		// and Bitcoin's Merkle rule is to hash it with itself. Mirrors
		// ts-sdk's MerklePath.findOrComputeLeaf/cachedFindLeaf.
		if len(ip) == 1 {
			var maxOffset uint64
			for o := range ip[0] {
				if o > maxOffset {
					maxOffset = o
				}
			}
			if prevOffset == offsetAtHeight(maxOffset, layer-1) {
				return &PathElement{Offset: offset, Hash: MerkleTreeParent(left.Hash, left.Hash)}
			}
		}
		return nil
	}

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

// getOffsetLeaf returns the PathElement at (layer, offset), synthesizing a
// missing interior node from its two children when necessary. It reproduces
// IndexedPath.GetOffsetLeaf byte-for-byte — including its last-wins handling of
// duplicate offsets — without the eager per-level map allocation.
//
// The common case (a fully-populated or sparse proof BUMP) is served by a
// direct, allocation-free scan of the already-populated level and never
// synthesizes. Only when a node is genuinely missing and must be rebuilt from
// its children does it fall back to a per-level index, built once and lazily
// and threaded through *index, so the recursive synthesis stays O(1) per lookup
// and the whole climb stays O(N) even for compound/pruned paths (a plain
// linear-scan recursion would be O(N^2) for those). Fully-populated and proof
// paths never synthesize, so they never allocate the index.
func (mp *MerklePath) getOffsetLeaf(layer int, offset uint64, index *IndexedPath) *PathElement {
	// Direct last-wins lookup, matching the old map build's path[offset] = el
	// (a later entry overwrites an earlier one for the same offset).
	if layer < len(mp.Path) {
		level := mp.Path[layer]
		for i := len(level) - 1; i >= 0; i-- {
			if level[i].Offset == offset {
				return level[i]
			}
		}
	}
	if layer == 0 {
		return nil
	}

	// The node is missing and must be synthesized from its children. Build the
	// per-level index once so the recursive child lookups are O(1), then defer
	// to the existing (map-backed) synthesis.
	if *index == nil {
		*index = mp.buildIndexedPath()
	}
	return index.GetOffsetLeaf(layer, offset)
}

// buildIndexedPath builds the per-level offset->element index that ComputeRoot
// previously constructed eagerly. Later entries win for duplicate offsets,
// matching Go map-assignment semantics (and thus getOffsetLeaf's direct path).
func (mp *MerklePath) buildIndexedPath() IndexedPath {
	indexedPath := make(IndexedPath, len(mp.Path))
	for h, level := range mp.Path {
		m := make(map[uint64]*PathElement, len(level))
		for _, el := range level {
			m[el.Offset] = el
		}
		indexedPath[h] = m
	}
	return indexedPath
}

// Clone creates a deep copy of the MerklePath by serializing and deserializing.
func (mp *MerklePath) Clone() *MerklePath {
	if mp == nil {
		return nil
	}
	clone, _ := NewMerklePathFromBinary(mp.Bytes())
	return clone
}

// NewMerklePath creates a new MerklePath with the given block height and path
func NewMerklePath(blockHeight uint32, path [][]*PathElement) *MerklePath {
	return &MerklePath{
		BlockHeight: blockHeight,
		Path:        path,
	}
}

// NewMerklePathFromCoinbaseTxid creates a MerklePath for a transaction that is
// the only transaction in its block (typically a coinbase in an otherwise empty
// block). The merkle root equals the txid itself: a tree of height 1 with a
// single offset-0 leaf. This matches @bsv/sdk MerklePath.fromCoinbaseTxidAndHeight.
//
// Parameters:
// - txid: The transaction ID that is the sole leaf (and therefore the merkle root)
// - blockHeight: The height of the block that contains only this transaction
//
// Returns:
// - A MerklePath whose ComputeRoot equals txid, or an error if txid is nil
func NewMerklePathFromCoinbaseTxid(txid *chainhash.Hash, blockHeight uint32) (*MerklePath, error) {
	if txid == nil {
		return nil, errors.New("txid is required")
	}
	txidFlag := true
	return &MerklePath{
		BlockHeight: blockHeight,
		Path: [][]*PathElement{{
			{Offset: 0, Hash: txid, Txid: &txidFlag},
		}},
	}, nil
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

		// A leaf is at least an offset varint (>=1 byte) plus a flags byte.
		if err = guardParseCount(reader, uint64(nLeavesAtThisHeight), 2, "merkle path leaves"); err != nil {
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

	// @bsv/sdk rejects a repeated offset. ComputeRoot uses the first entry with
	// a hash, while a merge keeps the last, so a repeated level-0 offset can
	// drop a txid that still proves.
	if err := duplicateOffsetError(bump.Path); err != nil {
		return nil, err
	}

	// A single-level path with exactly one leaf is only valid as a block whose
	// sole transaction is its coinbase, which sits at offset 0. A lone leaf at
	// any other offset lacks its sibling and can never form a valid path, so
	// reject it at parse time rather than later computing a bogus root. This
	// mirrors @bsv/sdk.
	if len(bump.Path) == 1 && len(bump.Path[0]) == 1 && bump.Path[0][0].Offset != 0 {
		return nil, fmt.Errorf("invalid merkle path: a lone leaf must be at offset 0, found offset %d", bump.Path[0][0].Offset)
	}

	return bump, nil
}

// bytesLen returns the exact BRC-74 serialized length of the BUMP so Bytes can
// pre-size its buffer. It mirrors the byte layout produced by Bytes.
func (mp *MerklePath) bytesLen() int {
	size := util.VarInt(mp.BlockHeight).Length() + 1 // block-height varint + tree-height byte
	for level := 0; level < len(mp.Path); level++ {
		size += util.VarInt(len(mp.Path[level])).Length()
		for _, leaf := range mp.Path[level] {
			size += util.VarInt(leaf.Offset).Length() + 1 // offset varint + flags byte
			if leaf.Duplicate == nil || !*leaf.Duplicate {
				size += chainhash.HashSize
			}
		}
	}
	return size
}

// Bytes encodes a BUMP as a slice of bytes. BUMP Binary Format according to BRC-74 https://brc.dev/74
func (mp *MerklePath) Bytes() []byte {
	buf := make([]byte, 0, mp.bytesLen())
	buf = appendVarInt(buf, uint64(mp.BlockHeight))
	treeHeight := len(mp.Path)
	buf = append(buf, byte(treeHeight)) //nolint:gosec // G115 -- merkle tree height is bounded well within a byte
	for level := 0; level < treeHeight; level++ {
		buf = appendVarInt(buf, uint64(len(mp.Path[level])))
		for _, leaf := range mp.Path[level] {
			buf = appendVarInt(buf, leaf.Offset)
			flags := byte(0)
			if leaf.Duplicate != nil && *leaf.Duplicate {
				flags |= 1
			}
			if leaf.Txid != nil && *leaf.Txid {
				flags |= 2
			}
			buf = append(buf, flags)
			if (flags & 1) == 0 {
				buf = append(buf, leaf.Hash[:]...)
			}
		}
	}
	return buf
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

// ComputeRoot computes the Merkle root from a given transaction ID.
func (mp *MerklePath) ComputeRoot(txid *chainhash.Hash) (*chainhash.Hash, error) {
	return mp.computeRoot(txid, nil)
}

// computeRoot is ComputeRoot with an optional index shared across climbs.
// A nil sharedIndex builds the index lazily on the first synthesized lookup,
// so checking many txids does not rebuild it once per call.
func (mp *MerklePath) computeRoot(txid *chainhash.Hash, sharedIndex *IndexedPath) (*chainhash.Hash, error) {
	if mp == nil || len(mp.Path) == 0 || len(mp.Path[0]) == 0 {
		return nil, errors.New("merkle path has no leaves")
	}
	if txid == nil {
		for _, l := range mp.Path[0] {
			if l.Hash != nil {
				txid = l.Hash
				break
			}
		}
	}
	if txid == nil {
		return nil, errors.New("no valid leaf found in the Merkle Path")
	}
	if len(mp.Path) == 1 {
		// A single-level path with one leaf can only be a block whose sole
		// transaction is its coinbase: that leaf sits at offset 0 and is itself
		// the merkle root. A lone leaf at any other offset lacks the sibling
		// needed to climb the tree, so it has no root. This mirrors @bsv/sdk.
		if len(mp.Path[0]) == 1 {
			leaf := mp.Path[0][0]
			if leaf.Offset != 0 {
				return nil, fmt.Errorf("invalid merkle path: a lone leaf must be at offset 0, found offset %d", leaf.Offset)
			}
			if leaf.Hash == nil || !leaf.Hash.Equal(*txid) {
				return nil, fmt.Errorf("the BUMP does not contain the txid: %s", *txid)
			}
			return txid, nil
		}
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

	// Compute effective tree height from max offset (handles single-level compound paths)
	var maxOffset uint64
	for _, l := range mp.Path[0] {
		if l.Offset > maxOffset {
			maxOffset = l.Offset
		}
	}
	effectiveHeight := len(mp.Path)
	if bitsNeeded := bits.Len64(maxOffset); bitsNeeded > effectiveHeight {
		effectiveHeight = bitsNeeded
	}

	idx := sharedIndex
	if idx == nil {
		var local IndexedPath
		idx = &local
	}
	for height := 0; height < effectiveHeight; height++ {
		offset := (index >> height) ^ 1
		leaf := mp.getOffsetLeaf(height, offset, idx)
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
func (mp *MerklePath) VerifyHex(ctx context.Context, txidStr string, ct chaintracker.ChainTracker) (bool, error) {
	if txid, err := chainhash.NewHashFromHex(txidStr); err != nil {
		return false, err
	} else {
		return mp.Verify(ctx, txid, ct)
	}
}

func (mp *MerklePath) Verify(ctx context.Context, txid *chainhash.Hash, ct chaintracker.ChainTracker) (bool, error) {
	root, err := mp.ComputeRoot(txid)
	if err != nil {
		return false, err
	}
	return ct.IsValidRootForHeight(ctx, root, mp.BlockHeight)
}

// Combine merges other into the receiver.
//
// Both paths must share a block height and merkle root. The merge refuses a
// level/offset held by both paths with different contents, and refuses to drop
// a parent that both children can recompute unless that parent is their
// MerkleTreeParent. Every level-0 hash of either input that already proved the
// root must still do so when climbed from the offset ComputeRoot would use.
// m.Path is replaced only when those checks pass. other is not modified. On
// error, m is left unchanged.
func (m *MerklePath) Combine(other *MerklePath) error {
	if m == nil || other == nil {
		return errors.New("cannot combine a nil MerklePath")
	}
	if m.BlockHeight != other.BlockHeight {
		return errors.New("cannot combine MerklePaths with different block heights")
	}
	_, err := m.combineVerified(other, nil)
	return err
}

// combineVerified merges other into m after the caller has decided the paths
// belong to the same block. changed reports whether m.Path was replaced.
// cache, when non-nil, holds the receiver's proving hashes from the last
// merge and is updated to the merged path's proving hashes on success.
// On error m is left unchanged and cache is not updated.
func (m *MerklePath) combineVerified(other *MerklePath, cache *derivedBump) (bool, error) {
	if m == nil || other == nil {
		return false, errors.New("cannot combine a nil MerklePath")
	}
	if err := duplicateOffsetError(m.Path); err != nil {
		return false, err
	}
	if err := duplicateOffsetError(other.Path); err != nil {
		return false, err
	}
	expected, err := m.ComputeRoot(nil)
	if err != nil {
		return false, err
	}
	otherRoot, err := other.ComputeRoot(nil)
	if err != nil {
		return false, err
	}
	if !expected.IsEqual(otherRoot) {
		return false, errors.New("cannot combine MerklePaths with different roots")
	}

	height := len(m.Path)
	if len(other.Path) > height {
		height = len(other.Path)
	}
	left := indexPathLevels(m.Path)
	right := indexPathLevels(other.Path)
	levels := make([]map[uint64]*PathElement, height)
	for h := 0; h < height; h++ {
		levels[h] = make(map[uint64]*PathElement)
		var lmap, rmap map[uint64]*PathElement
		if h < len(left) {
			lmap = left[h]
		}
		if h < len(right) {
			rmap = right[h]
		}
		for off, el := range lmap {
			levels[h][off] = el
		}
		for off, el := range rmap {
			existing, ok := levels[h][off]
			if !ok {
				levels[h][off] = el
				continue
			}
			if !pathElementsCompatible(existing, el, lmap, rmap) {
				return false, fmt.Errorf("cannot combine MerklePaths with conflicting nodes at level %d offset %d", h, off)
			}
			levels[h][off] = preferPathElement(existing, el)
		}
	}

	for h := 1; h < len(levels); h++ {
		for off, el := range levels[h] {
			leftChild, hasLeft := levels[h-1][off*2]
			rightChild, hasRight := levels[h-1][off*2+1]
			if !hasLeft || !hasRight {
				continue
			}
			parent, ok := merkleParentOf(leftChild, rightChild)
			if !ok {
				continue
			}
			match, known := nodeMatchesParent(el, parent, levels[h])
			if !known {
				continue
			}
			if !match {
				return false, fmt.Errorf("cannot combine MerklePaths: node at level %d offset %d does not match its children", h, off)
			}
			delete(levels[h], off)
		}
	}

	newPath := make([][]*PathElement, height)
	for h := range levels {
		newPath[h] = make([]*PathElement, 0, len(levels[h]))
		for _, el := range levels[h] {
			newPath[h] = append(newPath[h], el)
		}
		slices.SortFunc(newPath[h], func(a, b *PathElement) int {
			return int(a.Offset) - int(b.Offset) //nolint:gosec // G115 -- merkle path offsets are bounded well within int range by tree size
		})
	}
	if pathsEqual(m.Path, newPath) {
		return false, nil
	}

	// Every level-0 hash that already proved expected, from either input, must
	// still do so when climbed the way ComputeRoot climbs: from the lowest
	// offset that holds that hash, and from the lowest hashed offset overall.
	nextProving, err := mergedLevel0StillProves(left, right, levels, expected, cache)
	if err != nil {
		return false, err
	}

	m.Path = newPath
	if cache != nil {
		cache.proving = nextProving
		cache.provingKnown = true
		invalidateResolved(cache.resolved, left, levels)
	}
	return true, nil
}

func invalidateResolved(resolved map[dirtyKey]*chainhash.Hash, before, after []map[uint64]*PathElement) {
	if len(resolved) == 0 {
		return
	}
	height := len(before)
	if len(after) > height {
		height = len(after)
	}
	forEachChangedNode(before, after, func(h int, off uint64) {
		for hh := h; hh <= height+1; hh++ {
			delete(resolved, dirtyKey{h: hh, off: off})
			off >>= 1
		}
	})
}

// forEachChangedNode calls fn for every level/offset whose stored element
// differs between before and after, including additions and removals.
func forEachChangedNode(before, after []map[uint64]*PathElement, fn func(h int, off uint64)) {
	height := len(before)
	if len(after) > height {
		height = len(after)
	}
	for h := 0; h < height; h++ {
		var beforeLevel, afterLevel map[uint64]*PathElement
		if h < len(before) {
			beforeLevel = before[h]
		}
		if h < len(after) {
			afterLevel = after[h]
		}
		seen := make(map[uint64]struct{}, len(beforeLevel))
		for off, el := range beforeLevel {
			seen[off] = struct{}{}
			other, ok := afterLevel[off]
			if !ok || !pathElementEqual(el, other) {
				fn(h, off)
			}
		}
		for off := range afterLevel {
			if _, ok := seen[off]; ok {
				continue
			}
			fn(h, off)
		}
	}
}

// duplicateOffsetError reports a repeated offset in one level. @bsv/sdk rejects
// the same shape. A merge keeps the last entry at an offset and ComputeRoot
// uses the first, so a repeat can drop a txid that still proves.
func duplicateOffsetError(path [][]*PathElement) error {
	for h, level := range path {
		seen := make(map[uint64]struct{}, len(level))
		for _, el := range level {
			if el == nil {
				continue
			}
			if _, ok := seen[el.Offset]; ok {
				return fmt.Errorf("duplicate offset %d at height %d", el.Offset, h)
			}
			seen[el.Offset] = struct{}{}
		}
	}
	return nil
}

// combineNodeKey identifies a memoized node in a merge-time climb.
type combineNodeKey struct {
	height int
	offset uint64
}

// combineMemo is one memoized lookup. found is false when the node cannot be
// resolved; dup means the stored node is a duplicate marker.
type combineMemo struct {
	found bool
	dup   bool
	hash  *chainhash.Hash
}

// combineClimber computes merkle roots from the level maps a merge already
// built. Node lookups and the root above each node are memoized, so checking
// every level-0 leaf hashes each tree node once.
type combineClimber struct {
	levels      []map[uint64]*PathElement
	maxOffset   uint64
	singleLevel bool
	eff         int
	cache       map[combineNodeKey]combineMemo
	above       map[aboveKey]combineMemo
	resolved    map[dirtyKey]*chainhash.Hash
}

// aboveKey memoizes the tree root computed from a specific node hash.
// The hash is part of the key so a corrupted sibling cannot reuse an honest
// leaf's result.
type aboveKey struct {
	height int
	offset uint64
	self   chainhash.Hash
}

func newCombineClimber(levels []map[uint64]*PathElement) *combineClimber {
	return newCombineClimberResolved(levels, nil)
}

func newCombineClimberResolved(levels []map[uint64]*PathElement, resolved map[dirtyKey]*chainhash.Hash) *combineClimber {
	var maxOffset uint64
	if len(levels) > 0 {
		for off := range levels[0] {
			if off > maxOffset {
				maxOffset = off
			}
		}
	}
	eff := len(levels)
	if bitsNeeded := bits.Len64(maxOffset); bitsNeeded > eff {
		eff = bitsNeeded
	}
	return &combineClimber{
		levels:      levels,
		maxOffset:   maxOffset,
		singleLevel: len(levels) == 1,
		eff:         eff,
		cache:       make(map[combineNodeKey]combineMemo),
		above:       make(map[aboveKey]combineMemo),
		resolved:    resolved,
	}
}

func (c *combineClimber) node(height int, offset uint64) combineMemo {
	key := combineNodeKey{height, offset}
	if memo, ok := c.cache[key]; ok {
		return memo
	}
	if height < len(c.levels) {
		if el, ok := c.levels[height][offset]; ok && el != nil {
			if pathElementIsDuplicate(el) {
				memo := combineMemo{found: true, dup: true}
				c.cache[key] = memo
				return memo
			}
			if el.Hash != nil {
				memo := combineMemo{found: true, hash: el.Hash}
				c.cache[key] = memo
				return memo
			}
			c.cache[key] = combineMemo{}
			return combineMemo{}
		}
	}
	if c.resolved != nil {
		if prev, ok := c.resolved[dirtyKey{h: height, off: offset}]; ok {
			if prev == nil {
				c.cache[key] = combineMemo{}
				return combineMemo{}
			}
			memo := combineMemo{found: true, hash: prev}
			c.cache[key] = memo
			return memo
		}
	}
	var memo combineMemo
	if height == 0 {
		c.cache[key] = memo
		return memo
	}
	left := c.node(height-1, offset*2)
	if !left.found || left.hash == nil {
		c.cache[key] = memo
		return memo
	}
	right := c.node(height-1, offset*2+1)
	if right.dup || (c.singleLevel && offset*2 == offsetAtHeight(c.maxOffset, height-1) && !right.found) {
		memo = combineMemo{found: true, hash: MerkleTreeParent(left.hash, left.hash)}
		c.remember(height, offset, memo)
		return memo
	}
	if !right.found || right.hash == nil {
		c.cache[key] = memo
		return memo
	}
	memo = combineMemo{found: true, hash: MerkleTreeParent(left.hash, right.hash)}
	c.remember(height, offset, memo)
	return memo
}

func (c *combineClimber) remember(height int, offset uint64, memo combineMemo) {
	c.cache[combineNodeKey{height, offset}] = memo
	if c.resolved == nil || !memo.found || memo.dup || memo.hash == nil {
		return
	}
	c.resolved[dirtyKey{h: height, off: offset}] = memo.hash
}

// rootFrom climbs from a level-0 offset the way ComputeRoot does.
func (c *combineClimber) rootFrom(index uint64) (*chainhash.Hash, bool) {
	n := c.node(0, index)
	if !n.found || n.hash == nil {
		return nil, false
	}
	return c.upFromHash(0, index, n.hash)
}

// upFromHash is the tree root given the climb hash of (height, offset).
// Both children of one parent pass the same combined hash and share the result.
func (c *combineClimber) upFromHash(height int, offset uint64, self *chainhash.Hash) (*chainhash.Hash, bool) {
	if self == nil {
		return nil, false
	}
	if height >= c.eff {
		return self, true
	}
	key := aboveKey{height: height, offset: offset, self: *self}
	if memo, ok := c.above[key]; ok {
		return memo.hash, memo.found
	}
	sibOff := offset ^ 1
	sib := c.node(height, sibOff)
	var combined *chainhash.Hash
	switch {
	case !sib.found:
		c.above[key] = combineMemo{}
		return nil, false
	case sib.dup:
		combined = MerkleTreeParent(self, self)
	case sib.hash == nil:
		c.above[key] = combineMemo{}
		return nil, false
	case sibOff%2 != 0:
		combined = MerkleTreeParent(self, sib.hash)
	default:
		combined = MerkleTreeParent(sib.hash, self)
	}
	got, ok := c.upFromHash(height+1, offset>>1, combined)
	if !ok {
		c.above[key] = combineMemo{}
		return nil, false
	}
	c.above[key] = combineMemo{found: true, hash: got}
	return got, true
}

// mergedLevel0StillProves requires the merged path to keep proving every
// level-0 hash from either input that already computed expected. ComputeRoot
// starts at the lowest offset holding a hash, and ComputeRoot(nil) starts at
// the lowest hashed offset. cache, when it already knows the receiver's
// proving hashes, skips re-climbing leaves whose sibling chain did not change.
// The returned hashes are the ones the merged path proves, for the next merge.
func mergedLevel0StillProves(receiver, incoming, after []map[uint64]*PathElement, expected *chainhash.Hash, cache *derivedBump) ([]chainhash.Hash, error) {
	if expected == nil {
		return nil, errors.New("combined MerklePath has no root")
	}
	if len(after) == 0 || len(after[0]) == 0 {
		return nil, errors.New("combined MerklePath has no leaves")
	}
	lowest := fillHashOffsets(nil, after[0])
	if cache != nil {
		cache.scratchLow = fillHashOffsets(cache.scratchLow, after[0])
		lowest = cache.scratchLow
	}
	climb := newCombineClimber(after)
	seen := make(map[uint64]struct{})
	checkOffset := func(off uint64) error {
		if _, ok := seen[off]; ok {
			return nil
		}
		seen[off] = struct{}{}
		if loneOffsetZeroRoot(after, expected) && off == 0 {
			return nil
		}
		got, ok := climb.rootFrom(off)
		if !ok || !got.IsEqual(expected) {
			if got == nil {
				return fmt.Errorf("combined MerklePath no longer proves offset %d", off)
			}
			return fmt.Errorf("combined MerklePath root %s does not match original root %s", got, expected)
		}
		return nil
	}
	checkHash := func(h *chainhash.Hash) error {
		if h == nil {
			return errors.New("combined MerklePath no longer proves a level-0 leaf")
		}
		off, ok := lowest[*h]
		if !ok {
			return errors.New("combined MerklePath no longer proves a level-0 leaf")
		}
		return checkOffset(off)
	}
	offsetProves := func(off uint64) bool {
		if loneOffsetZeroRoot(after, expected) && off == 0 {
			return true
		}
		if _, ok := seen[off]; ok {
			return true
		}
		got, ok := climb.rootFrom(off)
		if ok && got.IsEqual(expected) {
			seen[off] = struct{}{}
			return true
		}
		return false
	}

	var receiverHashes []chainhash.Hash
	warm := cache != nil && cache.provingKnown
	if warm {
		receiverHashes = cache.proving
	} else if len(receiver) > 0 {
		receiverHashes = provingHashes(receiver, expected)
	}
	receiverAt := fillHashOffsets(nil, nil)
	if len(receiver) > 0 {
		receiverAt = fillHashOffsets(nil, receiver[0])
		if cache != nil {
			cache.scratchRecv = fillHashOffsets(cache.scratchRecv, receiver[0])
			receiverAt = cache.scratchRecv
		}
	}
	beforeEff := mergeEff(receiver)

	next := make([]chainhash.Hash, 0, len(receiverHashes)+8)
	inNext := make(map[chainhash.Hash]struct{}, len(receiverHashes)+8)
	add := func(h chainhash.Hash) {
		if _, ok := inNext[h]; ok {
			return
		}
		inNext[h] = struct{}{}
		next = append(next, h)
	}

	dirtyBits, allDirty := affectedLeafBits(receiver, after, beforeEff, climb.eff, cache)
	leafDirty := func(off uint64) bool {
		if allDirty {
			return true
		}
		i := int(off >> 3)
		return i < len(dirtyBits) && dirtyBits[i]&(1<<(off&7)) != 0
	}

	for _, h := range receiverHashes {
		offBefore, okBefore := receiverAt[h]
		offAfter, okAfter := lowest[h]
		if !okAfter {
			return nil, errors.New("combined MerklePath no longer proves a level-0 leaf")
		}
		if warm && okBefore && offBefore == offAfter && !leafDirty(offAfter) {
			add(h)
			continue
		}
		if err := checkOffset(offAfter); err != nil {
			return nil, err
		}
		add(h)
	}
	if len(incoming) > 0 {
		for _, h := range provingHashes(incoming, expected) {
			if err := checkHash(&h); err != nil {
				return nil, err
			}
			add(h)
		}
		for _, el := range incoming[0] {
			if el == nil || el.Hash == nil {
				continue
			}
			if _, ok := inNext[*el.Hash]; ok {
				continue
			}
			if off, ok := lowest[*el.Hash]; ok && offsetProves(off) {
				add(*el.Hash)
			}
		}
	}
	if len(receiver) > 0 {
		for _, el := range receiver[0] {
			if el == nil || el.Hash == nil {
				continue
			}
			if _, ok := inNext[*el.Hash]; ok {
				continue
			}
			offBefore, ok := receiverAt[*el.Hash]
			if !ok || !leafDirty(offBefore) {
				continue
			}
			if off, ok := lowest[*el.Hash]; ok && offsetProves(off) {
				add(*el.Hash)
			}
		}
	}
	for _, el := range after[0] {
		if el == nil || el.Hash == nil || !pathElementTxid(el) {
			continue
		}
		if err := checkHash(el.Hash); err != nil {
			return nil, err
		}
		add(*el.Hash)
	}
	var start uint64
	found := false
	for off, el := range after[0] {
		if el == nil || el.Hash == nil {
			continue
		}
		if !found || off < start {
			start = off
			found = true
		}
	}
	if !found {
		return nil, errors.New("combined MerklePath has no leaves")
	}
	if err := checkOffset(start); err != nil {
		return nil, err
	}
	if el := after[0][start]; el != nil && el.Hash != nil {
		add(*el.Hash)
	}
	return next, nil
}

// provingHashes lists level-0 hashes of levels that compute expected.
func provingHashes(levels []map[uint64]*PathElement, expected *chainhash.Hash) []chainhash.Hash {
	offsets := provingLeafOffsets(levels, expected)
	if len(levels) == 0 {
		return nil
	}
	out := make([]chainhash.Hash, 0, len(offsets))
	seen := make(map[chainhash.Hash]struct{}, len(offsets))
	for _, off := range offsets {
		el := levels[0][off]
		if el == nil || el.Hash == nil {
			continue
		}
		if _, ok := seen[*el.Hash]; ok {
			continue
		}
		seen[*el.Hash] = struct{}{}
		out = append(out, *el.Hash)
	}
	return out
}

type dirtyKey struct {
	h   int
	off uint64
}

// mergeDirty reports whether the resolved hash of a node changed between the
// receiver and the merged path. An unchanged stored node hides its children:
// the climb uses the stored hash. A newly stored node is clean when it equals
// the hash the receiver already synthesized there.
type mergeDirty struct {
	before      []map[uint64]*PathElement
	after       []map[uint64]*PathElement
	memo        map[dirtyKey]bool
	resolved    map[dirtyKey]*chainhash.Hash
	beforeClimb *combineClimber
	afterClimb  *combineClimber
}

func newMergeDirty(before, after []map[uint64]*PathElement, resolved map[dirtyKey]*chainhash.Hash) *mergeDirty {
	return &mergeDirty{before: before, after: after, memo: make(map[dirtyKey]bool), resolved: resolved}
}

func storedNode(levels []map[uint64]*PathElement, h int, off uint64) (*PathElement, bool) {
	if h < 0 || h >= len(levels) || levels[h] == nil {
		return nil, false
	}
	el, ok := levels[h][off]
	return el, ok && el != nil
}

func (d *mergeDirty) node(h int, off uint64) bool {
	if h < 0 {
		return false
	}
	key := dirtyKey{h, off}
	if v, ok := d.memo[key]; ok {
		return v
	}
	beforeEl, bok := storedNode(d.before, h, off)
	afterEl, aok := storedNode(d.after, h, off)
	var dirty bool
	switch {
	case bok && aok && pathElementEqual(beforeEl, afterEl):
		dirty = false
	case !bok && !aok:
		if h == 0 {
			dirty = false
		} else {
			dirty = d.node(h-1, off*2) || d.node(h-1, off*2+1)
		}
	case !bok && aok && h > 0 && afterEl.Hash != nil:
		if d.beforeClimb == nil {
			d.beforeClimb = newCombineClimberResolved(d.before, d.resolved)
		}
		prev := d.beforeClimb.node(h, off)
		dirty = !prev.found || prev.hash == nil || !prev.hash.Equal(*afterEl.Hash)
	case bok && !aok && h > 0 && beforeEl.Hash != nil:
		if d.afterClimb == nil {
			d.afterClimb = newCombineClimber(d.after)
		}
		now := d.afterClimb.node(h, off)
		dirty = !now.found || now.hash == nil || !now.hash.Equal(*beforeEl.Hash)
	default:
		dirty = true
	}
	d.memo[key] = dirty
	return dirty
}

// affectedLeafBits marks level-0 offsets whose climb can see a changed node.
// all is true when every offset must be rechecked.
func affectedLeafBits(before, after []map[uint64]*PathElement, beforeEff, afterEff int, cache *derivedBump) (bits []byte, all bool) {
	if beforeEff != afterEff {
		return nil, true
	}
	var maxOff uint64
	for _, levels := range [][]map[uint64]*PathElement{before, after} {
		if len(levels) == 0 {
			continue
		}
		for off := range levels[0] {
			if off > maxOff {
				maxOff = off
			}
		}
	}
	if maxOff > 1<<20 {
		return nil, true
	}
	d := newMergeDirty(before, after, nil)
	if cache != nil {
		if cache.resolved == nil {
			cache.resolved = make(map[dirtyKey]*chainhash.Hash)
		}
		d = newMergeDirty(before, after, cache.resolved)
	}
	bits = make([]byte, maxOff/8+1)
	mark := func(h int, sib uint64) {
		if !d.node(h, sib) {
			return
		}
		start := (sib ^ 1) << uint(h)
		end := start + (uint64(1) << uint(h))
		if start > maxOff {
			return
		}
		if end > maxOff+1 {
			end = maxOff + 1
		}
		for i := start; i < end; i++ {
			bits[i>>3] |= 1 << (i & 7)
		}
	}
	forEachChangedNode(before, after, mark)
	return bits, false
}

func mergeEff(levels []map[uint64]*PathElement) int {
	var maxOffset uint64
	if len(levels) > 0 {
		for off := range levels[0] {
			if off > maxOffset {
				maxOffset = off
			}
		}
	}
	eff := len(levels)
	if n := bits.Len64(maxOffset); n > eff {
		eff = n
	}
	return eff
}

// fillHashOffsets maps each level-0 hash to the smallest offset that holds it,
// reusing dst when it is non-nil. This matches ComputeRoot's first-match scan
// of a level sorted by offset.
func fillHashOffsets(dst map[chainhash.Hash]uint64, level map[uint64]*PathElement) map[chainhash.Hash]uint64 {
	if dst == nil {
		dst = make(map[chainhash.Hash]uint64, len(level))
	} else {
		clear(dst)
	}
	for off, el := range level {
		if el == nil || el.Hash == nil {
			continue
		}
		if prev, ok := dst[*el.Hash]; !ok || off < prev {
			dst[*el.Hash] = off
		}
	}
	return dst
}

// loneOffsetZeroRoot reports the coinbase shortcut: one level, one leaf at
// offset 0, and that leaf's hash is the root. The climb has no sibling.
func loneOffsetZeroRoot(levels []map[uint64]*PathElement, expected *chainhash.Hash) bool {
	if expected == nil || len(levels) != 1 || len(levels[0]) != 1 {
		return false
	}
	el, ok := levels[0][0]
	return ok && el != nil && el.Hash != nil && el.Hash.Equal(*expected)
}

// provingLeafOffsets lists level-0 offsets of before whose stored hash computes
// expected. A lone offset-0 leaf is the coinbase shortcut: its hash is the root
// and the climb has no sibling.
func provingLeafOffsets(before []map[uint64]*PathElement, expected *chainhash.Hash) []uint64 {
	if len(before) == 0 || len(before[0]) == 0 {
		return nil
	}
	if len(before) == 1 && len(before[0]) == 1 {
		if el, ok := before[0][0]; ok && el != nil && el.Hash != nil && el.Hash.Equal(*expected) {
			return []uint64{0}
		}
	}
	climb := newCombineClimber(before)
	offsets := make([]uint64, 0, len(before[0]))
	for off, el := range before[0] {
		if el == nil || el.Hash == nil {
			continue
		}
		got, ok := climb.rootFrom(off)
		if ok && got.IsEqual(expected) {
			offsets = append(offsets, off)
		}
	}
	return offsets
}

func indexPathLevels(path [][]*PathElement) []map[uint64]*PathElement {
	out := make([]map[uint64]*PathElement, len(path))
	for h, level := range path {
		indexed := make(map[uint64]*PathElement, len(level))
		for _, el := range level {
			if el == nil {
				continue
			}
			indexed[el.Offset] = el // last entry wins, matching the previous merge
		}
		out[h] = indexed
	}
	return out
}

func pathElementIsDuplicate(el *PathElement) bool {
	return el != nil && el.Duplicate != nil && *el.Duplicate
}

func pathElementTxid(el *PathElement) bool {
	return el != nil && el.Txid != nil && *el.Txid
}

// pathElementsCompatible reports whether two nodes at the same level and offset
// describe the same tree node. A hash matches a duplicate marker only when the
// input that stores the marker also stores the sibling it copies, and the hash
// equals that sibling. The other input's sibling does not count: above level 0
// that sibling is often computed rather than stored, so the other proof could
// supply both the sibling and a garbage hash.
func pathElementsCompatible(a, b *PathElement, left, right map[uint64]*PathElement) bool {
	if a == nil || b == nil {
		return false
	}
	aDup, bDup := pathElementIsDuplicate(a), pathElementIsDuplicate(b)
	if aDup && bDup {
		return true
	}
	if !aDup && !bDup {
		if a.Hash == nil || b.Hash == nil {
			return a.Hash == nil && b.Hash == nil
		}
		return a.Hash.Equal(*b.Hash)
	}
	hashed, dup := a, b
	home := right
	if aDup {
		hashed, dup = b, a
		home = left
	}
	if hashed.Hash == nil || home == nil {
		return false
	}
	sib, ok := home[siblingOffset(dup.Offset)]
	return ok && sib != nil && sib.Hash != nil && hashed.Hash.Equal(*sib.Hash)
}

// preferPathElement keeps a hash when the other node is only a duplicate
// marker, and preserves a txid flag set on either input without mutating it.
func preferPathElement(existing, incoming *PathElement) *PathElement {
	chosen := existing
	if chosen.Hash == nil && incoming.Hash != nil {
		chosen = incoming
	}
	if pathElementTxid(existing) || pathElementTxid(incoming) {
		return withTxidFlag(chosen)
	}
	return chosen
}

func withTxidFlag(el *PathElement) *PathElement {
	if pathElementTxid(el) {
		return el
	}
	flag := true
	cp := *el
	cp.Txid = &flag
	return &cp
}

// merkleParentOf is the parent hash of two children. A duplicate right child
// means the left child is hashed with itself. ok is false when the hash cannot
// be computed.
func merkleParentOf(left, right *PathElement) (*chainhash.Hash, bool) {
	if left == nil || left.Hash == nil {
		return nil, false
	}
	if pathElementIsDuplicate(right) {
		return MerkleTreeParent(left.Hash, left.Hash), true
	}
	if right == nil || right.Hash == nil {
		return nil, false
	}
	return MerkleTreeParent(left.Hash, right.Hash), true
}

// nodeMatchesParent reports whether el's value is parent. known is false when
// el is a duplicate marker whose sibling hash is not available to compare.
func nodeMatchesParent(el *PathElement, parent *chainhash.Hash, level map[uint64]*PathElement) (match bool, known bool) {
	if el == nil || parent == nil {
		return false, false
	}
	if el.Hash != nil {
		return el.Hash.Equal(*parent), true
	}
	if !pathElementIsDuplicate(el) {
		return false, false
	}
	sib := level[siblingOffset(el.Offset)]
	if sib == nil || sib.Hash == nil {
		return false, false
	}
	return sib.Hash.Equal(*parent), true
}

func pathsEqual(a, b [][]*PathElement) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !levelEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

func levelEqual(a, b []*PathElement) bool {
	if len(a) != len(b) {
		return false
	}
	indexed := make(map[uint64]*PathElement, len(b))
	for _, el := range b {
		if el == nil {
			return false
		}
		if _, exists := indexed[el.Offset]; exists {
			return false
		}
		indexed[el.Offset] = el
	}
	if len(indexed) != len(a) {
		return false
	}
	for _, el := range a {
		other, ok := indexed[el.Offset]
		if !ok || !pathElementEqual(el, other) {
			return false
		}
	}
	return true
}

func pathElementEqual(a, b *PathElement) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Offset != b.Offset || pathElementIsDuplicate(a) != pathElementIsDuplicate(b) || pathElementTxid(a) != pathElementTxid(b) {
		return false
	}
	if a.Hash == nil || b.Hash == nil {
		return a.Hash == nil && b.Hash == nil
	}
	return a.Hash.Equal(*b.Hash)
}

// FindLeafByOffset finds a PathElement at the given offset in the specified level.
// Returns nil if not found.
func (mp *MerklePath) FindLeafByOffset(level int, offset uint64) *PathElement {
	if level < 0 || level >= len(mp.Path) {
		return nil
	}
	for _, leaf := range mp.Path[level] {
		if leaf.Offset == offset {
			return leaf
		}
	}
	return nil
}

// AddLeaf adds a PathElement to the specified level.
// Grows the Path slice if necessary to accommodate the level.
func (mp *MerklePath) AddLeaf(level int, element *PathElement) {
	// Grow Path slice if needed
	for len(mp.Path) <= level {
		mp.Path = append(mp.Path, []*PathElement{})
	}
	mp.Path[level] = append(mp.Path[level], element)
}

// ComputeMissingHashes walks up the tree from level 0 and computes parent hashes
// where both children are present but the parent is missing.
// This allows building a complete merkle path from sparse data.
func (mp *MerklePath) ComputeMissingHashes() {
	if len(mp.Path) < 2 {
		return
	}

	for level := 1; level < len(mp.Path); level++ {
		prevLevel := mp.Path[level-1]

		for _, leftLeaf := range prevLevel {
			// Only process left children (even offsets)
			if leftLeaf.Hash == nil || (leftLeaf.Offset&1) != 0 {
				continue
			}

			rightOffset := leftLeaf.Offset + 1
			rightLeaf := mp.FindLeafByOffset(level-1, rightOffset)

			parentOffset := leftLeaf.Offset >> 1

			// Skip if parent already exists
			if mp.FindLeafByOffset(level, parentOffset) != nil {
				continue
			}

			// Compute parent if we have both children
			if rightLeaf != nil && rightLeaf.Hash != nil {
				parentHash := MerkleTreeParent(leftLeaf.Hash, rightLeaf.Hash)
				mp.Path[level] = append(mp.Path[level], &PathElement{
					Offset: parentOffset,
					Hash:   parentHash,
				})
			} else if rightLeaf != nil && rightLeaf.Duplicate != nil && *rightLeaf.Duplicate {
				parentHash := MerkleTreeParent(leftLeaf.Hash, leftLeaf.Hash)
				mp.Path[level] = append(mp.Path[level], &PathElement{
					Offset: parentOffset,
					Hash:   parentHash,
				})
			}
		}

		// If this level has an odd number of computed nodes and the leaves
		// form a contiguous set, add a duplicate marker for the last node.
		// This mirrors Bitcoin's Merkle tree behavior where an unpaired
		// node is hashed with itself.
		if len(mp.Path[level]) > 0 {
			var maxOffset uint64
			for _, leaf := range mp.Path[level] {
				if leaf.Offset > maxOffset {
					maxOffset = leaf.Offset
				}
			}
			if maxOffset&1 == 0 && maxOffset > 0 {
				// Even max offset with more than one node means odd count.
				// Verify it's contiguous by checking the previous offset exists.
				if mp.FindLeafByOffset(level, maxOffset-1) != nil {
					dup := true
					mp.Path[level] = append(mp.Path[level], &PathElement{
						Offset:    maxOffset + 1,
						Duplicate: &dup,
					})
				}
			}
		}
	}

	// Sort each level by offset for consistency
	for _, level := range mp.Path {
		slices.SortFunc(level, func(a, b *PathElement) int {
			return int(a.Offset) - int(b.Offset) //nolint:gosec // G115 -- merkle path offsets are bounded well within int range by tree size
		})
	}
}

// siblingOffset returns the offset of the node paired with offset at the same
// tree level (even offsets pair with offset+1, odd offsets with offset-1).
func siblingOffset(offset uint64) uint64 {
	if offset%2 == 0 {
		return offset + 1
	}
	return offset - 1
}

// offsetAtHeight returns the ancestor offset of a level-0 offset at the given
// height (each level up halves the offset), mirroring ts-sdk's
// offsetAtHeight helper in MerklePath.ts.
func offsetAtHeight(offset uint64, height int) uint64 {
	return offset >> uint(height)
}

// sameNodeAtHeight reports whether index and maxOffset land on the same
// ancestor node at the given height, mirroring ts-sdk's sameNodeAtHeight.
func sameNodeAtHeight(index, maxOffset uint64, height int) bool {
	return offsetAtHeight(index, height) == offsetAtHeight(maxOffset, height)
}

// extractCacheKey identifies a (height, offset) node for cachedFindLeafForExtract's memo table.
type extractCacheKey struct {
	height int
	offset uint64
}

// cachedFindLeafForExtract finds or synthesizes the PathElement at
// (height, offset), memoizing results (including "not found", cached as a
// present key mapping to nil) so repeated climbs across multiple requested
// txids share work. It mirrors ts-sdk's MerklePath.cachedFindLeaf exactly,
// including its handling of a single-level compound path's unpaired last
// node (treated as self-duplicated via sameNodeAtHeight).
func (mp *MerklePath) cachedFindLeafForExtract(
	height int,
	offset uint64,
	sourceIndex IndexedPath,
	cache map[extractCacheKey]*PathElement,
	maxOffset uint64,
) *PathElement {
	key := extractCacheKey{height, offset}
	if leaf, ok := cache[key]; ok {
		return leaf
	}

	if height < len(sourceIndex) {
		if leaf, ok := sourceIndex[height][offset]; ok {
			cache[key] = leaf
			return leaf
		}
	}
	if height == 0 {
		cache[key] = nil
		return nil
	}

	h := height - 1
	l := offset * 2
	leaf0 := mp.cachedFindLeafForExtract(h, l, sourceIndex, cache, maxOffset)
	if leaf0 == nil || leaf0.Hash == nil {
		cache[key] = nil
		return nil
	}

	leaf1 := mp.cachedFindLeafForExtract(h, l+1, sourceIndex, cache, maxOffset)
	if leaf1 == nil || leaf1.Hash == nil {
		leaf1IsDuplicate := leaf1 != nil && leaf1.Duplicate != nil && *leaf1.Duplicate
		if leaf1IsDuplicate || (len(mp.Path) == 1 && l == offsetAtHeight(maxOffset, h)) {
			result := &PathElement{Offset: offset, Hash: MerkleTreeParent(leaf0.Hash, leaf0.Hash)}
			cache[key] = result
			return result
		}
		cache[key] = nil
		return nil
	}

	var parentHash *chainhash.Hash
	if leaf1.Duplicate != nil && *leaf1.Duplicate {
		parentHash = MerkleTreeParent(leaf0.Hash, leaf0.Hash)
	} else {
		parentHash = MerkleTreeParent(leaf0.Hash, leaf1.Hash)
	}
	result := &PathElement{Offset: offset, Hash: parentHash}
	cache[key] = result
	return result
}

// trim removes internal nodes that are not required to prove the level-0
// txid-flagged nodes (any node whose value can instead be recomputed from
// nodes already kept), leaving every level sorted by increasing offset. It
// mirrors ts-sdk's MerklePath.trim and assumes every genuinely needed node is
// already present.
func (mp *MerklePath) trim() {
	for _, level := range mp.Path {
		slices.SortFunc(level, func(a, b *PathElement) int {
			return int(a.Offset) - int(b.Offset) //nolint:gosec // G115 -- merkle path offsets are bounded well within int range by tree size
		})
	}
	if len(mp.Path) == 0 || len(mp.Path[0]) == 0 {
		return
	}

	pushIfNew := func(v uint64, a []uint64) []uint64 {
		if len(a) == 0 || a[len(a)-1] != v {
			return append(a, v)
		}
		return a
	}

	dropOffsetsFromLevel := func(dropOffsets []uint64, level int) {
		for _, off := range dropOffsets {
			for i, n := range mp.Path[level] {
				if n.Offset == off {
					mp.Path[level] = append(mp.Path[level][:i], mp.Path[level][i+1:]...)
					break
				}
			}
		}
	}

	var computedOffsets []uint64
	var dropOffsets []uint64

	level0 := mp.Path[0]
	for l, n := range level0 {
		if n.Txid != nil && *n.Txid {
			// level 0 must enable computing level 1 for txid nodes.
			computedOffsets = pushIfNew(offsetAtHeight(n.Offset, 1), computedOffsets)
			continue
		}
		isOdd := n.Offset%2 == 1
		peerIdx := l + 1
		if isOdd {
			peerIdx = l - 1
		}
		if peerIdx < 0 || peerIdx >= len(level0) {
			continue
		}
		peer := level0[peerIdx]
		if peer.Txid == nil || !*peer.Txid {
			// drop non-txid level 0 nodes without a txid peer.
			dropOffsets = pushIfNew(peer.Offset, dropOffsets)
		}
	}
	dropOffsetsFromLevel(dropOffsets, 0)

	for h := 1; h < len(mp.Path); h++ {
		dropOffsets = computedOffsets
		var next []uint64
		for _, o := range dropOffsets {
			next = pushIfNew(offsetAtHeight(o, 1), next)
		}
		computedOffsets = next
		dropOffsetsFromLevel(dropOffsets, h)
	}
}

// Extract returns a new, minimal compound MerklePath proving membership for
// exactly the given txids, mirroring ts-sdk's MerklePath.extract (BRC-74
// sub-proof extraction). The receiver must be a compound path that already
// contains every requested txid as a level-0 leaf (for example, a full
// block's worth of level-0 txids, or a previously extracted/trimmed compound
// path); the returned path's computed root is checked to match the
// receiver's before it is returned.
func (mp *MerklePath) Extract(txids []*chainhash.Hash) (*MerklePath, error) {
	if mp == nil || len(mp.Path) == 0 || len(mp.Path[0]) == 0 {
		return nil, errors.New("merkle path has no leaves")
	}
	if len(txids) == 0 {
		return nil, errors.New("at least one txid must be provided to extract")
	}

	originalRoot, err := mp.ComputeRoot(nil)
	if err != nil {
		return nil, err
	}

	var maxOffset uint64
	for _, l := range mp.Path[0] {
		if l.Offset > maxOffset {
			maxOffset = l.Offset
		}
	}
	treeHeight := len(mp.Path)
	if h := bits.Len64(maxOffset); h > treeHeight {
		treeHeight = h
	}

	sourceIndex := mp.buildIndexedPath()
	cache := make(map[extractCacheKey]*PathElement)

	txidToOffset := make(map[chainhash.Hash]uint64, len(mp.Path[0]))
	for _, l := range mp.Path[0] {
		if l.Hash != nil {
			txidToOffset[*l.Hash] = l.Offset
		}
	}

	neededPerLevel := make([]map[uint64]*PathElement, treeHeight)
	for h := range neededPerLevel {
		neededPerLevel[h] = make(map[uint64]*PathElement)
	}

	for _, txid := range txids {
		if txid == nil {
			return nil, errors.New("nil txid provided to extract")
		}
		txOffset, ok := txidToOffset[*txid]
		if !ok {
			return nil, fmt.Errorf("transaction ID %s not found in the Merkle Path", txid)
		}

		txidFlag := true
		hashCopy := *txid
		neededPerLevel[0][txOffset] = &PathElement{Offset: txOffset, Txid: &txidFlag, Hash: &hashCopy}

		levelZeroSibling := siblingOffset(txOffset)
		if _, exists := neededPerLevel[0][levelZeroSibling]; !exists {
			if sib := mp.cachedFindLeafForExtract(0, levelZeroSibling, sourceIndex, cache, maxOffset); sib != nil {
				neededPerLevel[0][levelZeroSibling] = sib
			}
		}

		for h := 1; h < treeHeight; h++ {
			so := siblingOffset(offsetAtHeight(txOffset, h))
			if _, exists := neededPerLevel[h][so]; exists {
				continue
			}
			if sib := mp.cachedFindLeafForExtract(h, so, sourceIndex, cache, maxOffset); sib != nil {
				neededPerLevel[h][so] = sib
			} else if sameNodeAtHeight(txOffset, maxOffset, h) {
				dup := true
				neededPerLevel[h][so] = &PathElement{Offset: so, Duplicate: &dup}
			}
		}
	}

	newPath := make([][]*PathElement, treeHeight)
	for h, level := range neededPerLevel {
		leaves := make([]*PathElement, 0, len(level))
		for _, el := range level {
			leaves = append(leaves, el)
		}
		sort.Slice(leaves, func(i, j int) bool { return leaves[i].Offset < leaves[j].Offset })
		newPath[h] = leaves
	}

	compound := &MerklePath{BlockHeight: mp.BlockHeight, Path: newPath}
	compound.trim()

	extractedRoot, err := compound.ComputeRoot(nil)
	if err != nil {
		return nil, err
	}
	if !extractedRoot.IsEqual(originalRoot) {
		return nil, fmt.Errorf("extracted path root %s does not match original root %s", extractedRoot, originalRoot)
	}

	return compound, nil
}
