package storage

import (
	"context"
	"testing"

	"github.com/bsv-blockchain/go-sdk/overlay"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorageDownloader_InvalidURL(t *testing.T) {
	downloader := NewStorageDownloader(DownloaderConfig{Network: overlay.NetworkMainnet})

	// Test with invalid URL
	_, err := downloader.Download(context.Background(), "invalid-url")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid parameter UHRP url")
}

func TestStorageDownloader_IsValidURL(t *testing.T) {
	// Test with valid and invalid URLs
	// Note: For this test to pass, we need actual valid UHRP URLs
	// which requires proper SHA-256 hashes and checksums
	// Let's create valid ones from test hash values
	testHash1 := crypto.Sha256([]byte("test content 1"))
	testHash2 := crypto.Sha256([]byte("test content 2"))

	validURL1, err := GetURLForHash(testHash1)
	require.NoError(t, err)

	validURL2, err := GetURLForHash(testHash2)
	require.NoError(t, err)

	// Test cases with our freshly-generated valid URLs
	validURLs := []string{
		validURL1,
		validURL2,
	}

	invalidURLs := []string{
		"",
		"http://example.com",
		"invalid-url",
		"uhrp:invalid",
		"web+uhrp:invalid",
	}

	for _, url := range validURLs {
		t.Run("Valid: "+url, func(t *testing.T) {
			assert.True(t, IsValidURL(url))
		})
	}

	for _, url := range invalidURLs {
		t.Run("Invalid: "+url, func(t *testing.T) {
			assert.False(t, IsValidURL(url))
		})
	}
}

func TestStorageDownloader_UrlHashRoundTrip(t *testing.T) {
	// Test getting URL from hash and vice versa
	testData := []byte("hello world")
	hash := crypto.Sha256(testData)

	// Get URL from hash
	url, err := GetURLForHash(hash)
	require.NoError(t, err)
	assert.NotEmpty(t, url)
	assert.True(t, IsValidURL(url))

	// Get hash from URL back
	extractedHash, err := GetHashFromURL(url)
	require.NoError(t, err)
	assert.Equal(t, hash, extractedHash)
}

func TestStorageDownloader_HashURLValidation(t *testing.T) {
	// Test that hash validation works correctly
	hash1 := crypto.Sha256([]byte("content 1"))
	hash2 := crypto.Sha256([]byte("content 2"))

	url1, err := GetURLForHash(hash1)
	require.NoError(t, err)

	url2, err := GetURLForHash(hash2)
	require.NoError(t, err)

	// Verify distinct URLs
	assert.NotEqual(t, url1, url2)

	// Verify normalization handling
	assert.True(t, IsValidURL("uhrp://"+NormalizeURL(url1)))
	assert.True(t, IsValidURL("web+uhrp://"+NormalizeURL(url1)))
}

func TestStorageDownloader_GetURLForFile(t *testing.T) {
	// Test generating URL for a file
	content := []byte("test file content")

	url, err := GetURLForFile(content)
	require.NoError(t, err)
	assert.NotEmpty(t, url)

	// Verify hash can be extracted back
	hash, err := GetHashFromURL(url)
	require.NoError(t, err)

	// Verify hash matches expected
	expectedHash := crypto.Sha256(content)
	assert.Equal(t, expectedHash, hash)
}

// IntegrationTestDownloader would test the actual integrated functionality
// But is only meant to be run in environments where real lookup services exist
func TestStorageDownloader_Integration(t *testing.T) {
	// This test is skipped by default as it requires a real network connection
	t.Skip("Skipping integration test - requires real network connection")

	downloader := NewStorageDownloader(DownloaderConfig{Network: overlay.NetworkMainnet})

	// Use a real UHRP URL that should resolve to something in mainnet
	uhrpURL := "uhrp://2NEpo7TZRRrLZSi2U" // Example only

	// Test resolve
	hosts, err := downloader.Resolve(context.Background(), uhrpURL)
	require.NoError(t, err)
	require.NotEmpty(t, hosts)

	// Download should succeed with real URL
	result, err := downloader.Download(context.Background(), uhrpURL)
	require.NoError(t, err)
	assert.NotEmpty(t, result.Data)
	assert.NotEmpty(t, result.MimeType)
}
