package primitives

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// DRBGVector represents a single test vector for DRBG testing
type DRBGVector struct {
	Name     string   `json:"name"`
	Entropy  string   `json:"entropy"`
	Nonce    string   `json:"nonce"`
	Add      []string `json:"add"` // Changed to a slice of strings if it's an array
	Expected string   `json:"expected"`
}

// ReadDRBGVectors reads and parses the test vectors from a JSON file
func ReadDRBGVectors(filename string) ([]DRBGVector, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var vectors []DRBGVector
	err = json.Unmarshal(file, &vectors)
	return vectors, err
}
func TestHmacDRBG(t *testing.T) {
	vectors, err := ReadDRBGVectors("testdata/vectors.json")
	if err != nil {
		t.Fatalf("Failed to read DRBG vectors: %v", err)
	}

	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			entropy, _ := hex.DecodeString(vector.Entropy)
			nonce, _ := hex.DecodeString(vector.Nonce)
			expected, _ := hex.DecodeString(vector.Expected)

			t.Logf("Testing vector: %s\n", vector.Name)
			t.Logf("Entropy: %x, Nonce: %x, Expected Length: %d\n", entropy, nonce, len(expected))

			drbg, err := NewDRBG(entropy, nonce)
			if err != nil {
				t.Fatalf("Failed to create DRBG: %v", err)
			}

			var last []byte
			for range vector.Add {
				last, _ = drbg.Generate(len(expected)) // Ensure this is the correct length
			}

			if !compareSlices(last, expected) {
				t.Errorf("DRBG output did not match expected for %s\nExpected: %x\nGot: %x", vector.Name, expected, last)
			}
		})
	}
}

// compareSlices compares two byte slices for equality
func compareSlices(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
