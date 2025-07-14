package primitives

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"

	aesgcm "github.com/bsv-blockchain/go-sdk/primitives/aesgcm"
)

type SymmetricKey struct {
	key []byte
}

// Encrypt encrypts the given message using the symmetric key using AES-GCM
func (s *SymmetricKey) Encrypt(message []byte) (ciphertext []byte, err error) {
	iv := make([]byte, 32)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}
	ciphertext, tag, err := aesgcm.AESGCMEncrypt(message, s.ToBytes(), iv, []byte{})
	if err != nil {
		return nil, err
	}

	result := make([]byte, len(iv)+len(ciphertext)+len(tag))

	copy(result, iv)
	copy(result[len(iv):], ciphertext)
	copy(result[len(iv)+len(ciphertext):], tag)
	return result, nil
}

// Decrypt decrypts the given message using the symmetric key using AES-GCM
func (s *SymmetricKey) Decrypt(message []byte) (plaintext []byte, err error) {
	// Check if the message is too short to be a valid encrypted message
	if len(message) < 32+16 {
		return nil, errors.New("message is too short to be a valid encrypted message")
	}

	iv := message[:32]
	ciphertext := message[32 : len(message)-16]
	tag := message[len(message)-16:]
	plaintext, err = aesgcm.AESGCMDecrypt(ciphertext, s.ToBytes(), iv, []byte{}, tag)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (s *SymmetricKey) ToBytes() []byte {
	return s.key
}

func (s *SymmetricKey) FromBytes(b []byte) *SymmetricKey {
	return &SymmetricKey{key: b}
}

func NewSymmetricKey(key []byte) *SymmetricKey {
	if len(key) < 32 {
		// Pad the key to 32 bytes if it's shorter
		paddedKey := make([]byte, 32)
		copy(paddedKey[32-len(key):], key)
		key = paddedKey
	}
	return &SymmetricKey{key: key}
}

func NewSymmetricKeyFromRandom() *SymmetricKey {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return &SymmetricKey{key: key}
}

func NewSymmetricKeyFromString(keyBase64String string) *SymmetricKey {
	// Decode the Base64 string to bytes
	keyBytes, err := base64.StdEncoding.DecodeString(keyBase64String)
	if err != nil {
		log.Fatalf("Failed to decode Base64 symmetric key string: %v", err)
	}
	return &SymmetricKey{key: keyBytes}
}
