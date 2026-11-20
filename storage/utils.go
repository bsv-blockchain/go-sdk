// Package storage provides interfaces and utilities for working with UHRP-based file storage.
package storage

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	base58 "github.com/bsv-blockchain/go-sdk/compat/base58"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
)

const (
	uhrpScheme     = "uhrp:"
	webScheme      = "web+uhrp:"
	minHashLength  = 32
	prefixLength   = 2
	checksumLength = 4

	// urlPayloadLength is the decoded length of a UHRP URL: the 2-byte prefix,
	// the 32-byte SHA-256 hash and the 4-byte checksum.
	urlPayloadLength = prefixLength + minHashLength + checksumLength
)

// uhrpBase58CheckPrefix is the 2-byte prefix [0xce, 0x00] used in Base58Check
// encoding of UHRP URLs, matching the TypeScript SDK's
var uhrpBase58CheckPrefix = []byte{0xce, 0x00}

var (
	// ErrInvalidHashLength is returned when a hash length is incorrect
	ErrInvalidHashLength = errors.New("hash length must be 32 bytes (sha256)")

	// ErrInvalidURLPrefix is returned when a UHRP URL has an invalid prefix
	ErrInvalidURLPrefix = errors.New("bad prefix")

	// ErrInvalidURLLength is returned when a UHRP URL does not decode to exactly
	// 38 bytes (the 2-byte prefix, the 32-byte hash and the 4-byte checksum)
	ErrInvalidURLLength = errors.New("invalid length")

	// ErrInvalidChecksum is returned when the checksum validation fails
	ErrInvalidChecksum = errors.New("invalid checksum")

	// ErrInvalidBase58 is returned when a UHRP URL is not valid Base58; the
	// returned error also wraps the decoder's error
	ErrInvalidBase58 = errors.New("invalid base58 encoding")
)

// NormalizeURL removes the scheme from a UHRP URL and returns the Base58Check
// string that remains. As in the TypeScript SDK's normalizeURL, a leading
// "uhrp:" (in any case) is removed and then a leading "//", so "uhrp:<base58>",
// "uhrp://<base58>" and "//<base58>" all normalize to "<base58>". The
// "web+uhrp:" scheme used by browser protocol handlers is removed the same way.
// Input without these prefixes is returned unchanged, and the result is not
// validated.
func NormalizeURL(url string) string {
	switch {
	case hasPrefixFold(url, webScheme):
		url = url[len(webScheme):]
	case hasPrefixFold(url, uhrpScheme):
		url = url[len(uhrpScheme):]
	}
	return strings.TrimPrefix(url, "//")
}

// hasPrefixFold reports whether s begins with prefix, ignoring case.
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// GetURLForHash generates a UHRP URL from a given SHA-256 hash using Base58Check encoding with a [0xce, 0x00] prefix.
func GetURLForHash(hash []byte) (string, error) {
	if len(hash) != minHashLength {
		return "", ErrInvalidHashLength
	}

	payload := make([]byte, 0, urlPayloadLength)
	payload = append(payload, uhrpBase58CheckPrefix...)
	payload = append(payload, hash...)

	checksum := crypto.Sha256d(payload)[:checksumLength]
	payload = append(payload, checksum...)

	return base58.Encode(payload), nil
}

// GetURLForFile generates a UHRP URL for a file
func GetURLForFile(data []byte) (string, error) {
	hash := crypto.Sha256(data)
	return GetURLForHash(hash)
}

// GetHashFromURL extracts the SHA-256 hash from a UHRP URL, after NormalizeURL
// has removed any scheme. Each failure can be told apart with errors.Is:
//   - ErrInvalidBase58: the URL is not valid Base58
//   - ErrInvalidURLLength: the URL does not decode to exactly 38 bytes
//   - ErrInvalidURLPrefix: the 2-byte prefix is not [0xce, 0x00]
//   - ErrInvalidChecksum: the 4-byte checksum does not match
func GetHashFromURL(uhrpURL string) ([]byte, error) {
	normalized := NormalizeURL(uhrpURL)

	// Decode base58 string
	decoded, err := base58.Decode(normalized)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidBase58, err)
	}

	// Check exact length: prefixLength (2) + hash (32) + checksum (4)
	if len(decoded) != urlPayloadLength {
		return nil, fmt.Errorf("%w: decoded %d bytes, want %d", ErrInvalidURLLength, len(decoded), urlPayloadLength)
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
	expectedChecksum := crypto.Sha256d(decoded[:prefixLength+minHashLength])[:checksumLength]
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
