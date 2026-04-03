package storage

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test vectors from the TypeScript SDK's StorageUtils.test.ts to test compatibility
const (
	tsTestHashHex = "1a5ec49a3f32cd56d19732e89bde5d81755ddc0fd8515dc8b226d47654139dca"
	tsTestURL     = "XUT6PqWb3GP3LR7dmBMCJwZ3oo5g1iGCF3CrpzyuJCemkGu1WGoq"
	tsTestFileHex = "687da27f04a112aa48f1cab2e7949f1eea4f7ba28319c1e999910cd561a634a05a3516e6db"
)

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "already normalized",
			input:    "abcdef12345",
			expected: "abcdef12345",
		},
		{
			name:     "uhrp protocol prefix",
			input:    "uhrp://abcdef12345",
			expected: "abcdef12345",
		},
		{
			name:     "uhrp uppercase protocol prefix",
			input:    "UHRP://abcdef12345",
			expected: "abcdef12345",
		},
		{
			name:     "web+uhrp protocol prefix",
			input:    "web+uhrp://abcdef12345",
			expected: "abcdef12345",
		},
		{
			name:     "web+uhrp uppercase protocol prefix",
			input:    "WEB+UHRP://abcdef12345",
			expected: "abcdef12345",
		},
		{
			name:     "new base58check format unchanged",
			input:    tsTestURL,
			expected: tsTestURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeURL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetURLForHash_MatchesTypeScriptSDK(t *testing.T) {
	// This is the primary cross-SDK compatibility test.
	// The expected URL must match the TypeScript SDK's output exactly.
	testHash, err := hex.DecodeString(tsTestHashHex)
	require.NoError(t, err)

	url, err := GetURLForHash(testHash)
	require.NoError(t, err)
	assert.Equal(t, tsTestURL, url, "GetURLForHash output must match TypeScript SDK test vector")
}

func TestGetURLForHashAndGetHashFromURL(t *testing.T) {
	testHash, err := hex.DecodeString(tsTestHashHex)
	require.NoError(t, err)

	// Generate URL from hash
	url, err := GetURLForHash(testHash)
	require.NoError(t, err)

	// Make sure URL is not empty and matches expected format
	assert.NotEmpty(t, url)
	assert.Equal(t, tsTestURL, url)
	assert.True(t, IsValidURL(url))

	// Extract hash back from URL — round-trip test
	extractedHash, err := GetHashFromURL(url)
	require.NoError(t, err)
	assert.Equal(t, testHash, extractedHash)
}

func TestGetURLForFile(t *testing.T) {
	fileBytes, err := hex.DecodeString(tsTestFileHex)
	require.NoError(t, err)

	// The TS test asserts that getURLForFile(exampleFile) == exampleURL
	url, err := GetURLForFile(fileBytes)
	require.NoError(t, err)
	assert.Equal(t, tsTestURL, url, "GetURLForFile must match TypeScript SDK test vector")
	assert.True(t, IsValidURL(url))
}

func TestGetHashFromURL_WithProtocolPrefix(t *testing.T) {
	testHash, err := hex.DecodeString(tsTestHashHex)
	require.NoError(t, err)

	// Test with uhrp:// prefix (NormalizeURL strips it, then we decode the base58check)
	urlWithPrefix := "uhrp://" + tsTestURL
	extractedHash, err := GetHashFromURL(urlWithPrefix)
	require.NoError(t, err)
	assert.Equal(t, testHash, extractedHash)

	// Test with web+uhrp:// prefix
	webUrlWithPrefix := "web+uhrp://" + tsTestURL
	extractedHash, err = GetHashFromURL(webUrlWithPrefix)
	require.NoError(t, err)
	assert.Equal(t, testHash, extractedHash)
}

func TestIsValidURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid URL - new format",
			input:    tsTestURL,
			expected: true,
		},
		{
			name:     "valid URL with uhrp:// prefix",
			input:    "uhrp://" + tsTestURL,
			expected: true,
		},
		{
			name:     "valid URL with web+uhrp:// prefix",
			input:    "web+uhrp://" + tsTestURL,
			expected: true,
		},
		{
			name:     "invalid URL - empty",
			input:    "",
			expected: false,
		},
		{
			name:     "invalid URL - wrong characters",
			input:    "not-a-valid-url",
			expected: false,
		},
		{
			name:     "invalid URL - modified valid URL (bad checksum)",
			input:    tsTestURL[:len(tsTestURL)-1] + "X",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidURL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetURLForHash_InvalidInputs(t *testing.T) {
	// Test with invalid hash length
	_, err := GetURLForHash([]byte{1, 2, 3}) // Too short
	assert.Error(t, err)
}

func TestGetHashFromURL_InvalidInputs(t *testing.T) {
	// Test with completely invalid input
	_, err := GetHashFromURL("not-base58")
	assert.Error(t, err)

	// Modify a valid URL to invalidate the checksum
	invalidURL := tsTestURL[:len(tsTestURL)-1] + "X"
	_, err = GetHashFromURL(invalidURL)
	assert.Error(t, err)

	// TS SDK test: known bad checksum URL
	badChecksumURL := "XUU7cTfy6fA6q2neLDmzPqJnGB6o18PXKoGaWLPrH1SeWLKgdCKq"
	_, err = GetHashFromURL(badChecksumURL)
	assert.Error(t, err)
}
