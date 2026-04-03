package storage

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeURL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetURLForHashAndGetHashFromURL(t *testing.T) {
	// Sample test data - use a known hash
	testHash, err := hex.DecodeString("1a5ec49a3f32cd56d19732e89bde5d81755ddc0fd8515dc8b226d47654139dca")
	require.NoError(t, err)

	// Generate URL from hash
	url, err := GetURLForHash(testHash)
	require.NoError(t, err)

	// Make sure URL is not empty and looks reasonable
	assert.NotEmpty(t, url)
	assert.True(t, len(url) > 10)
	assert.True(t, IsValidURL(url))

	// Extract hash from URL
	extractedHash, err := GetHashFromURL(url)
	require.NoError(t, err)

	// Hash should match original
	assert.Equal(t, testHash, extractedHash)

	// Test with protocol prefix
	urlWithPrefix := "uhrp://" + NormalizeURL(url)
	extractedHash, err = GetHashFromURL(urlWithPrefix)
	require.NoError(t, err)
	assert.Equal(t, testHash, extractedHash)

	// Test with web protocol prefix
	webUrlWithPrefix := "web+uhrp://" + NormalizeURL(url)
	extractedHash, err = GetHashFromURL(webUrlWithPrefix)
	require.NoError(t, err)
	assert.Equal(t, testHash, extractedHash)
}

func TestGetURLForFile(t *testing.T) {
	// Sample file content from TypeScript tests
	fileHex := "687da27f04a112aa48f1cab2e7949f1eea4f7ba28319c1e999910cd561a634a05a3516e6db"
	fileBytes, err := hex.DecodeString(fileHex)
	require.NoError(t, err)

	// Generate URL for file
	url, err := GetURLForFile(fileBytes)
	require.NoError(t, err)

	// URL should not be empty
	assert.NotEmpty(t, url)

	// We should be able to validate the URL
	assert.True(t, IsValidURL(url))
}

func TestIsValidURL(t *testing.T) {
	// Sample test data - use a known hash
	testHash, err := hex.DecodeString("1a5ec49a3f32cd56d19732e89bde5d81755ddc0fd8515dc8b226d47654139dca")
	require.NoError(t, err)

	// Generate valid URL from hash
	validURL, err := GetURLForHash(testHash)
	require.NoError(t, err)

	// Test various URL forms
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid URL",
			input:    validURL,
			expected: true,
		},
		{
			name:     "valid URL with protocol prefix",
			input:    "uhrp://" + NormalizeURL(validURL),
			expected: true,
		},
		{
			name:     "valid URL with web protocol prefix",
			input:    "web+uhrp://" + NormalizeURL(validURL),
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
			name:     "invalid URL - modified valid URL",
			input:    validURL[:len(validURL)-1] + "X",
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

	// Create a URL with a valid hash but modify the checksum
	testHash, err := hex.DecodeString("1a5ec49a3f32cd56d19732e89bde5d81755ddc0fd8515dc8b226d47654139dca")
	require.NoError(t, err)

	validURL, err := GetURLForHash(testHash)
	require.NoError(t, err)

	// Modify the last character to invalidate the checksum
	if len(validURL) > 0 {
		invalidURL := validURL[:len(validURL)-1] + "X"
		_, err = GetHashFromURL(invalidURL)
		assert.Error(t, err)
	}
}
