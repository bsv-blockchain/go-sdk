// Package storage provides interfaces and utilities for working with UHRP-based file storage.
package storage

import (
	"bytes"
	"errors"
	"strings"

	base58 "github.com/bsv-blockchain/go-sdk/compat/base58"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
)

const (
	uhrpPrefix    = "uhrp://"
	webPrefix     = "web+uhrp://"
	minHashLength = 32
)

var (
	// ErrInvalidHashLength is returned when a hash length is incorrect
	ErrInvalidHashLength = errors.New("hash length must be 32 bytes (sha256)")

	// ErrInvalidURLPrefix is returned when a UHRP URL has an invalid prefix
	ErrInvalidURLPrefix = errors.New("bad prefix")

	// ErrInvalidURLLength is returned when a UHRP URL data section has incorrect length
	ErrInvalidURLLength = errors.New("invalid length")

	// ErrInvalidChecksum is returned when the checksum validation fails
	ErrInvalidChecksum = errors.New("invalid checksum")
)

// NormalizeURL removes any prefix from the provided UHRP URL and returns the cleaned version
func NormalizeURL(url string) string {
	lowerURL := strings.ToLower(url)
	if strings.HasPrefix(lowerURL, webPrefix) {
		return url[len(webPrefix):]
	}
	if strings.HasPrefix(lowerURL, uhrpPrefix) {
		return url[len(uhrpPrefix):]
	}
	return url
}

// GetURLForHash generates a UHRP URL from a given SHA-256 hash
func GetURLForHash(hash []byte) (string, error) {
	if len(hash) != minHashLength {
		return "", errors.New("hash must be exactly 32 bytes (SHA-256)")
	}

	// Append checksum (double SHA-256 of the hash, first 4 bytes)
	checksum := crypto.Sha256d(hash)[:4]
	data := append(hash, checksum...)

	// Encode with base58
	encoded := base58.Encode(data)
	return uhrpPrefix + encoded, nil
}

// GetURLForFile generates a UHRP URL for a file
func GetURLForFile(data []byte) (string, error) {
	hash := crypto.Sha256(data)
	return GetURLForHash(hash)
}

// GetHashFromURL extracts the SHA-256 hash from a UHRP URL
func GetHashFromURL(uhrpURL string) ([]byte, error) {
	normalized := NormalizeURL(uhrpURL)

	// Decode base58 string
	decoded, err := base58.Decode(normalized)
	if err != nil {
		return nil, errors.New("invalid UHRP URL: base58 decode failed")
	}

	// Check minimum length (hash + checksum)
	if len(decoded) < minHashLength+4 {
		return nil, errors.New("invalid UHRP URL: too short after decoding")
	}

	// Split into hash and checksum
	hash := decoded[:minHashLength]
	checksum := decoded[minHashLength:]

	// Verify checksum
	expectedChecksum := crypto.Sha256d(hash)[:4]
	if !bytes.Equal(checksum, expectedChecksum) {
		return nil, errors.New("invalid UHRP URL: checksum verification failed")
	}

	return hash, nil
}

// IsValidURL checks if a URL is a valid UHRP URL
func IsValidURL(uhrpURL string) bool {
	_, err := GetHashFromURL(uhrpURL)
	return err == nil
}
