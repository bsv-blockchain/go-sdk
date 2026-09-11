package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/wallet"
)

// setupMockWalletForAuth creates a mock wallet with the required methods for auth operations
func setupMockWalletForAuth(t *testing.T) *wallet.TestWallet {
	testWallet := wallet.NewTestWalletForRandomKey(t)

	// Return a dummy signature result
	testWallet.OnCreateSignature().ReturnSuccess(&wallet.CreateSignatureResult{})

	testWallet.OnVerifySignature().ReturnSuccess(&wallet.VerifySignatureResult{
		Valid: true,
	})

	return testWallet
}

func TestNewUploader(t *testing.T) {
	t.Parallel()
	// Test with valid config
	mockWallet := wallet.NewTestWalletForRandomKey(t)
	config := UploaderConfig{
		StorageURL: "https://example.com/storage",
		Wallet:     mockWallet,
	}

	uploader, err := NewUploader(config)
	require.NoError(t, err)
	assert.NotNil(t, uploader)
	assert.Equal(t, config.StorageURL, uploader.baseURL)
	assert.NotNil(t, uploader.authFetch)

	// Test with empty storage URL
	config = UploaderConfig{
		StorageURL: "",
		Wallet:     mockWallet,
	}

	uploader, err = NewUploader(config)
	require.Error(t, err)
	assert.Nil(t, uploader)
	assert.Contains(t, err.Error(), "storage URL is required")

	// Test with nil wallet
	config = UploaderConfig{
		StorageURL: "https://example.com/storage",
		Wallet:     nil,
	}

	uploader, err = NewUploader(config)
	require.Error(t, err)
	assert.Nil(t, uploader)
	assert.Contains(t, err.Error(), "wallet is required")
}

func TestStorageUploader_PublishFile(t *testing.T) {
	t.Parallel()
	// Inject an AuthFetcher that fails so the request errors out without touching
	// the network, verifying the uploader is wired past config validation.
	mockWallet := setupMockWalletForAuth(t)
	uploader, err := NewUploader(UploaderConfig{
		StorageURL: "https://example.com/storage",
		Wallet:     mockWallet,
	}, WithAuthFetcher(erroringFetcher(assert.AnError)))
	require.NoError(t, err)
	assert.NotNil(t, uploader)
	assert.Equal(t, "https://example.com/storage", uploader.baseURL)
	assert.NotNil(t, uploader.authFetch)

	// Test file data
	testFile := UploadableFile{
		Data: []byte("test file content"),
		Type: "text/plain",
	}

	// This fails at the injected auth fetch, not at configuration validation.
	_, err = uploader.PublishFile(context.Background(), testFile, 60)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "storage URL is required")
	assert.NotContains(t, err.Error(), "wallet is required")
}

func TestStorageUploader_FindFile(t *testing.T) {
	t.Parallel()
	mockWallet := setupMockWalletForAuth(t)
	uploader, err := NewUploader(UploaderConfig{
		StorageURL: "https://example.com/storage",
		Wallet:     mockWallet,
	}, WithAuthFetcher(erroringFetcher(assert.AnError)))
	require.NoError(t, err)
	assert.NotNil(t, uploader)

	_, err = uploader.FindFile(context.Background(), "uhrp://test123")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "storage URL is required")
	assert.NotContains(t, err.Error(), "wallet is required")
}

// TestUploadFileResult tests the file upload result structure
func TestUploadFileResult(t *testing.T) {
	t.Parallel()
	// Test creating upload result
	result := UploadFileResult{
		Published: true,
		UhrpURL:   "uhrp://abc123def456",
	}

	assert.True(t, result.Published)
	assert.Equal(t, "uhrp://abc123def456", result.UhrpURL)
}

// TestFindFileData tests the find file data structure
func TestFindFileData(t *testing.T) {
	t.Parallel()
	// Test creating find result
	result := FindFileData{
		Name:       "test.txt",
		Size:       "1024 bytes",
		MimeType:   "text/plain",
		ExpiryTime: 1672531200,
	}

	assert.Equal(t, "test.txt", result.Name)
	assert.Equal(t, "1024 bytes", result.Size)
	assert.Equal(t, "text/plain", result.MimeType)
	assert.Equal(t, int64(1672531200), result.ExpiryTime)
}

func TestStorageUploader_ListUploads(t *testing.T) {
	t.Parallel()
	mockWallet := setupMockWalletForAuth(t)
	uploader, err := NewUploader(UploaderConfig{
		StorageURL: "https://example.com/storage",
		Wallet:     mockWallet,
	}, WithAuthFetcher(erroringFetcher(assert.AnError)))
	require.NoError(t, err)

	_, err = uploader.ListUploads(context.Background())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "storage URL is required")
	assert.NotContains(t, err.Error(), "wallet is required")
}

func TestStorageUploader_RenewFile(t *testing.T) {
	t.Parallel()
	mockWallet := setupMockWalletForAuth(t)
	uploader, err := NewUploader(UploaderConfig{
		StorageURL: "https://example.com/storage",
		Wallet:     mockWallet,
	}, WithAuthFetcher(erroringFetcher(assert.AnError)))
	require.NoError(t, err)

	_, err = uploader.RenewFile(context.Background(), "uhrp://test123", 60)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "storage URL is required")
	assert.NotContains(t, err.Error(), "wallet is required")
}
