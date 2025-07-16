package primitives

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSymmetricKeyEncryptionAndDecryption(t *testing.T) {
	t.Logf("Running encryption and decryption without errors")
	symmetricKey := NewSymmetricKeyFromRandom()
	cipherText, err := symmetricKey.Encrypt([]byte("a thing to encrypt"))
	if err != nil {
		t.Errorf("Error encrypting: %v", err)
	}

	decrypted, err := symmetricKey.Decrypt(cipherText)
	if err != nil {
		t.Errorf("Error decrypting: %v", err)
	}

	if string(decrypted) != "a thing to encrypt" {
		t.Errorf("Decrypted value does not match original plaintext")
	}
}

type symmetricTestVector struct {
	Key        string `json:"key"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
}

func TestSymmetricKeyDecryption(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	testdataPath := filepath.Join(filepath.Dir(currentFile), "testdata", "SymmetricKey.vectors.json")

	require.True(t, ok, "Could not determine the directory of the current test file")

	vectors, err := os.ReadFile(testdataPath)
	if err != nil {
		t.Fatalf("Error reading test vectors: %v", err)
	}

	var testVectors []symmetricTestVector

	err = json.Unmarshal(vectors, &testVectors)
	if err != nil {
		t.Fatalf("Error unmarshalling test vectors: %v", err)
	}

	for i, v := range testVectors {
		t.Logf("Running decryption test vector %d", i+1)

		vectorCiphertext, err := base64.StdEncoding.DecodeString(v.Ciphertext)
		if err != nil {
			log.Fatalf("Failed to decode ciphertext: %v", err)
		}

		symmetricKey := NewSymmetricKeyFromString(v.Key)
		decrypted, err := symmetricKey.Decrypt(vectorCiphertext)
		if err != nil {
			t.Errorf("Error decrypting: %v", err)
		}

		if string(decrypted) != v.Plaintext {
			t.Errorf("Decrypted value does not match expected plaintext")
		}

	}
}

func TestSymmetricKeyWith31ByteKeyEncryption(t *testing.T) {
	// Use a private key that generates a 31-byte X coordinate
	privKey, err := PrivateKeyFromWif("L4B2postXdaP7TiUrUBYs53Fqzheu7WhSoQVPuY8qBdoBeEwbmZx")
	require.NoError(t, err, "Failed to create private key from WIF")

	pubKey := privKey.PubKey()
	keyBytes := pubKey.X.Bytes()

	// Verify this is indeed a 31-byte key
	require.Equal(t, 31, len(keyBytes), "Expected 31-byte key")

	symmetricKey := NewSymmetricKey(keyBytes)
	plaintext := []byte("test message")

	// Test encryption
	ciphertext, err := symmetricKey.Encrypt(plaintext)
	require.NoError(t, err, "Failed to encrypt with 31-byte key")

	// Test decryption
	decrypted, err := symmetricKey.Decrypt(ciphertext)
	require.NoError(t, err, "Failed to decrypt with 31-byte key")
	require.Equal(t, plaintext, decrypted, "Decrypted text does not match original")
}

func TestSymmetricKeyWith32ByteKeyEncryption(t *testing.T) {
	// Use a private key that generates a 32-byte X coordinate
	privKey, err := PrivateKeyFromWif("KyLGEhYicSoGchHKmVC2fUx2MRrHzWqvwBFLLT4DZB93Nv5DxVR9")
	require.NoError(t, err, "Failed to create private key from WIF")

	pubKey := privKey.PubKey()
	keyBytes := pubKey.X.Bytes()

	// Verify this is indeed a 32-byte key
	require.Equal(t, 32, len(keyBytes), "Expected 32-byte key")

	symmetricKey := NewSymmetricKey(keyBytes)
	plaintext := []byte("test message")

	// Test encryption
	ciphertext, err := symmetricKey.Encrypt(plaintext)
	require.NoError(t, err, "Failed to encrypt with 32-byte key")

	// Test decryption
	decrypted, err := symmetricKey.Decrypt(ciphertext)
	require.NoError(t, err, "Failed to decrypt with 32-byte key")
	require.Equal(t, plaintext, decrypted, "Decrypted text does not match original")
}
