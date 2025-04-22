package storage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockWallet implements a minimal wallet.Interface for testing
type MockWallet struct {
	wallet.Interface
}

func TestNewStorageUploader(t *testing.T) {
	// Test with valid config
	config := UploaderConfig{
		StorageURL: "https://example.com/storage",
		Wallet:     &MockWallet{},
	}

	uploader, err := NewStorageUploader(config)
	require.NoError(t, err)
	assert.NotNil(t, uploader)
	assert.Equal(t, config.StorageURL, uploader.baseURL)
	assert.NotNil(t, uploader.authFetch)

	// Test with empty storage URL
	config = UploaderConfig{
		StorageURL: "",
		Wallet:     &MockWallet{},
	}

	uploader, err = NewStorageUploader(config)
	assert.Error(t, err)
	assert.Nil(t, uploader)
	assert.Contains(t, err.Error(), "storage URL is required")

	// Test with nil wallet
	config = UploaderConfig{
		StorageURL: "https://example.com/storage",
		Wallet:     nil,
	}

	uploader, err = NewStorageUploader(config)
	assert.Error(t, err)
	assert.Nil(t, uploader)
	assert.Contains(t, err.Error(), "wallet is required")
}

// This test demonstrates how to mock HTTP responses for the uploader
// It's marked as skipped since it can't run without a fully implemented mock wallet
func TestStorageUploader_PublishFile(t *testing.T) {
	t.Skip("Requires full wallet mock implementation")

	// Create a test server to mock the API responses
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/upload":
			// Mock the upload info response
			uploadInfoResp := map[string]interface{}{
				"status":          "success",
				"uploadURL":       "https://example.com/storage/upload/123",
				"requiredHeaders": map[string]string{"X-Auth": "token123"},
			}
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(uploadInfoResp); err != nil {
				t.Logf("Error encoding response: %v", err)
			}
		default:
			// Handle direct uploads
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	// Create uploader with the test server URL
	uploader, err := NewStorageUploader(UploaderConfig{
		StorageURL: server.URL,
		Wallet:     &MockWallet{},
	})
	require.NoError(t, err)

	// Test file upload
	file := UploadableFile{
		Data: []byte("test content"),
		Type: "text/plain",
	}

	result, err := uploader.PublishFile(context.Background(), file, 60)
	require.NoError(t, err)
	assert.True(t, result.Published)
	assert.NotEmpty(t, result.UhrpURL)
}

// This test is similar to the PublishFile test, but for FindFile
func TestStorageUploader_FindFile(t *testing.T) {
	t.Skip("Requires full wallet mock implementation")

	// Create a test server to mock the API responses
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/find" {
			// Mock the find response
			findResp := map[string]interface{}{
				"status": "success",
				"data": map[string]interface{}{
					"name":       "test.txt",
					"size":       "11 bytes",
					"mimeType":   "text/plain",
					"expiryTime": 1672531200,
				},
			}
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(findResp); err != nil {
				t.Logf("Error encoding response: %v", err)
			}
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create uploader with the test server URL
	uploader, err := NewStorageUploader(UploaderConfig{
		StorageURL: server.URL,
		Wallet:     &MockWallet{},
	})
	require.NoError(t, err)

	// Test find file
	result, err := uploader.FindFile(context.Background(), "uhrp://test123")
	require.NoError(t, err)
	assert.Equal(t, "test.txt", result.Name)
	assert.Equal(t, "11 bytes", result.Size)
	assert.Equal(t, "text/plain", result.MimeType)
	assert.Equal(t, int64(1672531200), result.ExpiryTime)
}
