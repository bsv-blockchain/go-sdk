package block

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bsv-blockchain/go-sdk/chainhash"
)

const (
	// HeaderSize is the size of a Bitcoin block header in bytes (80 bytes)
	HeaderSize = 80
)

// Header represents a Bitcoin block header (80 bytes)
type Header struct {
	Version    int32         // 4 bytes - Block version
	PrevBlock  chainhash.Hash // 32 bytes - Previous block hash
	MerkleRoot chainhash.Hash // 32 bytes - Merkle root hash
	Timestamp  uint32        // 4 bytes - Block timestamp (Unix time)
	Bits       uint32        // 4 bytes - Difficulty target
	Nonce      uint32        // 4 bytes - Nonce
}

// NewHeaderFromBytes creates a BlockHeader from an 80-byte slice
func NewHeaderFromBytes(data []byte) (*Header, error) {
	if len(data) != HeaderSize {
		return nil, fmt.Errorf("invalid header size: expected %d bytes, got %d", HeaderSize, len(data))
	}

	h := &Header{}
	r := bytes.NewReader(data)

	// Read version (4 bytes, little-endian)
	if err := binary.Read(r, binary.LittleEndian, &h.Version); err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}

	// Read previous block hash (32 bytes)
	if _, err := io.ReadFull(r, h.PrevBlock[:]); err != nil {
		return nil, fmt.Errorf("failed to read prev block hash: %w", err)
	}

	// Read merkle root (32 bytes)
	if _, err := io.ReadFull(r, h.MerkleRoot[:]); err != nil {
		return nil, fmt.Errorf("failed to read merkle root: %w", err)
	}

	// Read timestamp (4 bytes, little-endian)
	if err := binary.Read(r, binary.LittleEndian, &h.Timestamp); err != nil {
		return nil, fmt.Errorf("failed to read timestamp: %w", err)
	}

	// Read bits (4 bytes, little-endian)
	if err := binary.Read(r, binary.LittleEndian, &h.Bits); err != nil {
		return nil, fmt.Errorf("failed to read bits: %w", err)
	}

	// Read nonce (4 bytes, little-endian)
	if err := binary.Read(r, binary.LittleEndian, &h.Nonce); err != nil {
		return nil, fmt.Errorf("failed to read nonce: %w", err)
	}

	return h, nil
}

// NewHeaderFromHex creates a BlockHeader from a hex string (160 characters)
func NewHeaderFromHex(hexStr string) (*Header, error) {
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %w", err)
	}
	return NewHeaderFromBytes(data)
}

// Bytes serializes the block header to an 80-byte slice
func (h *Header) Bytes() []byte {
	buf := new(bytes.Buffer)
	buf.Grow(HeaderSize)

	// Write version (4 bytes, little-endian)
	binary.Write(buf, binary.LittleEndian, h.Version)

	// Write previous block hash (32 bytes)
	buf.Write(h.PrevBlock[:])

	// Write merkle root (32 bytes)
	buf.Write(h.MerkleRoot[:])

	// Write timestamp (4 bytes, little-endian)
	binary.Write(buf, binary.LittleEndian, h.Timestamp)

	// Write bits (4 bytes, little-endian)
	binary.Write(buf, binary.LittleEndian, h.Bits)

	// Write nonce (4 bytes, little-endian)
	binary.Write(buf, binary.LittleEndian, h.Nonce)

	return buf.Bytes()
}

// Hex returns the block header as a hex string
func (h *Header) Hex() string {
	return hex.EncodeToString(h.Bytes())
}

// Hash calculates the block hash (double SHA-256 of the header)
func (h *Header) Hash() chainhash.Hash {
	return chainhash.DoubleHashH(h.Bytes())
}

// String returns a string representation of the header
func (h *Header) String() string {
	return fmt.Sprintf("Header{Hash: %s, PrevBlock: %s, Height: ?, Bits: %d}",
		h.Hash().String(), h.PrevBlock.String(), h.Bits)
}
