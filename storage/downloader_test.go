package storage

import (
	"context"
	"testing"

	"github.com/bsv-blockchain/go-sdk/overlay"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockStorageDownloader implements StorageDownloaderInterface for testing
type MockStorageDownloader struct {
	ResolveResult  []string
	ResolveError   error
	DownloadResult DownloadResult
	DownloadError  error
}

func (m *MockStorageDownloader) Resolve(ctx context.Context, uhrpURL string) ([]string, error) {
	if m.ResolveError != nil {
		return nil, m.ResolveError
	}
	return m.ResolveResult, nil
}

func (m *MockStorageDownloader) Download(ctx context.Context, uhrpURL string) (DownloadResult, error) {
	if m.DownloadError != nil {
		return DownloadResult{}, m.DownloadError
	}
	return m.DownloadResult, nil
}

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

func TestStorageDownloader_MockedOperations(t *testing.T) {
	// Test the downloader interface using mocks to avoid network dependencies

	t.Run("Successful resolve operation", func(t *testing.T) {
		mockDownloader := &MockStorageDownloader{
			ResolveResult: []string{
				"https://host1.example.com/file123",
				"https://host2.example.com/file123",
			},
			ResolveError: nil,
		}

		hosts, err := mockDownloader.Resolve(context.Background(), "uhrp://test-url")
		require.NoError(t, err)
		assert.Len(t, hosts, 2)
		assert.Contains(t, hosts, "https://host1.example.com/file123")
		assert.Contains(t, hosts, "https://host2.example.com/file123")
	})

	t.Run("Successful download operation", func(t *testing.T) {
		testContent := []byte("test file content for download")

		mockDownloader := &MockStorageDownloader{
			DownloadResult: DownloadResult{
				Data:     testContent,
				MimeType: "text/plain",
			},
			DownloadError: nil,
		}

		result, err := mockDownloader.Download(context.Background(), "uhrp://test-url")
		require.NoError(t, err)
		assert.Equal(t, testContent, result.Data)
		assert.Equal(t, "text/plain", result.MimeType)
	})

	t.Run("Failed resolve operation", func(t *testing.T) {
		mockDownloader := &MockStorageDownloader{
			ResolveError: assert.AnError,
		}

		_, err := mockDownloader.Resolve(context.Background(), "uhrp://test-url")
		assert.Error(t, err)
	})

	t.Run("Failed download operation", func(t *testing.T) {
		mockDownloader := &MockStorageDownloader{
			DownloadError: assert.AnError,
		}

		_, err := mockDownloader.Download(context.Background(), "uhrp://test-url")
		assert.Error(t, err)
	})
}

func TestStorageDownloader_InterfaceCompliance(t *testing.T) {
	// Test that our real implementation satisfies the interface
	var _ StorageDownloaderInterface = NewStorageDownloader(DownloaderConfig{Network: overlay.NetworkMainnet})

	// Test that our mock implementation satisfies the interface
	var _ StorageDownloaderInterface = &MockStorageDownloader{}
}
