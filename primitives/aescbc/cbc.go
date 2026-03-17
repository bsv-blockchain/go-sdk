package primitives

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// AESCBCEncrypt encrypts data using AES in CBC mode with an IV.
// CBC mode with PKCS7 padding is required for BIP-level compatibility (e.g., ECIES).
func AESCBCEncrypt(data, key, iv []byte, concatIv bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	data = PKCS7Padd(data, block.BlockSize())
	blockModel := cipher.NewCBCEncrypter(block, iv) //NOSONAR CBC mode required by BIP/ECIES specification
	cipherText := make([]byte, len(data))
	blockModel.CryptBlocks(cipherText, data)
	if concatIv {
		cipherText = append(iv, cipherText...)
	}
	return cipherText, nil
}

// AESCBCDecrypt decrypts data using AES in CBC mode with an IV.
// CBC mode with PKCS7 padding is required for BIP-level compatibility (e.g., ECIES).
func AESCBCDecrypt(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockModel := cipher.NewCBCDecrypter(block, iv) //NOSONAR CBC mode required by BIP/ECIES specification
	plantText := make([]byte, len(data))
	blockModel.CryptBlocks(plantText, data)
	plantText, err = PKCS7Unpad(plantText, block.BlockSize())
	if err != nil {
		return nil, err
	}
	return plantText, nil
}

func PKCS7Padd(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

// PKCS7UnPadding removes padding from the plaintext
func PKCS7Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)

	// Check if the data length is a multiple of the block size or if it's empty
	if length%blockSize != 0 || length == 0 {
		return nil, errors.New("invalid padding length")
	}

	// Get the padding length from the last byte
	padding := int(data[length-1])

	// Check if the padding length is larger than the block size
	if padding > blockSize {
		return nil, errors.New("invalid padding byte (large)")
	}

	// Check all padding bytes to ensure they are consistent
	for _, v := range data[len(data)-padding:] {
		if int(v) != padding {
			return nil, errors.New("invalid padding byte (inconsistent)")
		}
	}

	// Return the data without padding
	return data[:(length - padding)], nil
}
