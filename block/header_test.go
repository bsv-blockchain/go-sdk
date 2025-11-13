package block

import (
	"encoding/hex"
	"testing"
)

func TestNewHeaderFromBytes(t *testing.T) {
	// Genesis block mainnet header
	genesisHex := "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
	genesisBytes, err := hex.DecodeString(genesisHex)
	if err != nil {
		t.Fatalf("Failed to decode genesis hex: %v", err)
	}

	header, err := NewHeaderFromBytes(genesisBytes)
	if err != nil {
		t.Fatalf("NewHeaderFromBytes() error = %v", err)
	}

	if header.Version != 1 {
		t.Errorf("Version = %d, want 1", header.Version)
	}

	if header.Timestamp != 1231006505 {
		t.Errorf("Timestamp = %d, want 1231006505", header.Timestamp)
	}

	if header.Bits != 0x1d00ffff {
		t.Errorf("Bits = %x, want 0x1d00ffff", header.Bits)
	}

	if header.Nonce != 2083236893 {
		t.Errorf("Nonce = %d, want 2083236893", header.Nonce)
	}
}

func TestHeaderBytes(t *testing.T) {
	genesisHex := "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
	genesisBytes, _ := hex.DecodeString(genesisHex)

	header, err := NewHeaderFromBytes(genesisBytes)
	if err != nil {
		t.Fatalf("NewHeaderFromBytes() error = %v", err)
	}

	serialized := header.Bytes()

	if len(serialized) != HeaderSize {
		t.Errorf("Bytes() returned %d bytes, want %d", len(serialized), HeaderSize)
	}

	if hex.EncodeToString(serialized) != genesisHex {
		t.Errorf("Bytes() = %s, want %s", hex.EncodeToString(serialized), genesisHex)
	}
}

func TestHeaderHex(t *testing.T) {
	genesisHex := "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"

	header, err := NewHeaderFromHex(genesisHex)
	if err != nil {
		t.Fatalf("NewHeaderFromHex() error = %v", err)
	}

	if header.Hex() != genesisHex {
		t.Errorf("Hex() = %s, want %s", header.Hex(), genesisHex)
	}
}

func TestHeaderHash(t *testing.T) {
	// Genesis block mainnet
	genesisHex := "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
	expectedHash := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

	header, err := NewHeaderFromHex(genesisHex)
	if err != nil {
		t.Fatalf("NewHeaderFromHex() error = %v", err)
	}

	hash := header.Hash()
	hashStr := hash.String()

	if hashStr != expectedHash {
		t.Errorf("Hash() = %s, want %s", hashStr, expectedHash)
	}
}

func TestNewHeaderFromBytesInvalidSize(t *testing.T) {
	invalidData := []byte{0x01, 0x02, 0x03}

	_, err := NewHeaderFromBytes(invalidData)
	if err == nil {
		t.Error("NewHeaderFromBytes() with invalid size should return error")
	}
}

func TestHeaderPrevBlockAndMerkleRoot(t *testing.T) {
	// Block 1 mainnet header
	block1Hex := "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299"
	expectedPrevBlock := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

	header, err := NewHeaderFromHex(block1Hex)
	if err != nil {
		t.Fatalf("NewHeaderFromHex() error = %v", err)
	}

	prevBlockStr := header.PrevBlock.String()
	if prevBlockStr != expectedPrevBlock {
		t.Errorf("PrevBlock = %s, want %s", prevBlockStr, expectedPrevBlock)
	}
}
