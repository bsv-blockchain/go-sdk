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
	prefixLength  = 2
)

// uhrpBase58CheckPrefix is the 2-byte prefix [0xce, 0x00] used in Base58Check
// encoding of UHRP URLs, matching the TypeScript SDK's
var uhrpBase58CheckPrefix = []byte{0xce, 0x00}

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

// GetURLForHash generates a UHRP URL from a given SHA-256 hash using Base58Check encoding with a [0xce, 0x00] prefix.
func GetURLForHash(hash []byte) (string, error) {
	if len(hash) != minHashLength {
		return "", ErrInvalidHashLength
	}

	payload := make([]byte, 0, prefixLength+minHashLength+4)
	payload = append(payload, uhrpBase58CheckPrefix...)
	payload = append(payload, hash...)

	checksum := crypto.Sha256d(payload)[:4]
	payload = append(payload, checksum...)

	return base58.Encode(payload), nil
}

// GetURLForFile generates a UHRP URL for a file
func GetURLForFile(data []byte) (string, error) {
	hash := crypto.Sha256(data)
	return GetURLForHash(hash)
}

// GetHashFromURL extracts the SHA-256 hash from a UHRP URL.
func GetHashFromURL(uhrpURL string) ([]byte, error) {
	normalized := NormalizeURL(uhrpURL)

	// Decode base58 string
	decoded, err := base58.Decode(normalized)
	if err != nil {
		return nil, errors.New("invalid UHRP URL: base58 decode failed")
	}

	// Check minimum length: prefixLength (2) + hash (32) + checksum (4)
	if len(decoded) != prefixLength+minHashLength+4 {
		return nil, errors.New("invalid UHRP URL: too short after decoding")
	}

	// Split into prefix, hash, and checksum
	prefix := decoded[:prefixLength]
	hash := decoded[prefixLength : prefixLength+minHashLength]
	checksum := decoded[prefixLength+minHashLength:]

	// Validate prefix
	if !bytes.Equal(prefix, uhrpBase58CheckPrefix) {
		return nil, ErrInvalidURLPrefix
	}

	// Verify checksum over prefix + hash
	expectedChecksum := crypto.Sha256d(decoded[:prefixLength+minHashLength])[:4]
	if !bytes.Equal(checksum, expectedChecksum) {
		return nil, ErrInvalidChecksum
	}

	return hash, nil
}

// IsValidURL checks if a URL is a valid UHRP URL
func IsValidURL(uhrpURL string) bool {
	_, err := GetHashFromURL(uhrpURL)
	return err == nil
}
