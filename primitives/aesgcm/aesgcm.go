package primitives

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// AESEncrypt performs AES single-block encryption (ECB) used internally as a building block
// for higher-level authenticated modes (GCM). This is not used standalone for data encryption.
func AESEncrypt(plaintext, key []byte) ([]byte, error) {
	if len(plaintext) != aes.BlockSize {
		return nil, fmt.Errorf("plaintext is not the correct block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize)
	block.Encrypt(ciphertext, plaintext) //NOSONAR single-block AES used as building block for GCM

	return ciphertext, nil
}

// AESDecrypt performs AES single-block decryption (ECB) used internally as a building block
// for higher-level authenticated modes (GCM). This is not used standalone for data decryption.
func AESDecrypt(ciphertext, key []byte) ([]byte, error) {
	if len(ciphertext) != aes.BlockSize {
		return nil, fmt.Errorf("ciphertext is not the correct block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, aes.BlockSize)
	block.Decrypt(plaintext, ciphertext) //NOSONAR single-block AES used as building block for GCM

	return plaintext, nil
}

// EncryptGCM encrypts plaintext using AES-GCM with the provided key and additional data
func AESGCMEncrypt(plaintext,
	key,
	initializationVector,
	additionalAuthenticatedData []byte,
) (ciphertext, authenticationTag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, len(initializationVector))
	if err != nil {
		return nil, nil, err
	}

	ciphertext = gcm.Seal(nil, initializationVector, plaintext, additionalAuthenticatedData)
	authenticationTag = ciphertext[len(ciphertext)-gcm.Overhead():]

	return ciphertext[:len(ciphertext)-gcm.Overhead()], authenticationTag, nil
}

// DecryptGCM decrypts ciphertext using AES-GCM with the provided key, nonce, additional data, and tag
func AESGCMDecrypt(ciphertext,
	key,
	initializationVector,
	additionalAuthenticatedData,
	authenticationTag []byte,
) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, len(initializationVector))
	if err != nil {
		return nil, err
	}

	ciphertextWithTag := append(ciphertext, authenticationTag...)
	plaintext, err = gcm.Open(nil, initializationVector, ciphertextWithTag, additionalAuthenticatedData)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
