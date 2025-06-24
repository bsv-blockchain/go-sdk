package storage

import (
	"context"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupMockWalletForAuth creates a mock wallet with the required methods for auth operations
func setupMockWalletForAuth(t *testing.T) *wallet.MockWallet {
	mockWallet := wallet.NewMockWallet(t)

	// Set up GetPublicKey response with proper identity key handling
	mockWallet.MockGetPublicKey = func(ctx context.Context, args wallet.GetPublicKeyArgs, originator string) (*wallet.GetPublicKeyResult, error) {
		t.Logf("GetPublicKey called with IdentityKey=%v, originator=%s", args.IdentityKey, originator)

		// Always return a valid public key - this is critical for auth
		// Using a known valid public key from other tests
		pubKeyHex := "03121a7afe56fc8e25bca4bb2c94f35eb67ebe5b84df2e149d65b9423ee65b8b4b"

		pubKey, err := ec.PublicKeyFromString(pubKeyHex)
		if err != nil {
			// This shouldn't happen with a valid hex string, but handle it defensively
			t.Fatalf("Failed to create test public key: %v", err)
		}

		return &wallet.GetPublicKeyResult{
			PublicKey: pubKey,
		}, nil
	}

	// Set up CreateHMAC response for nonce generation
	mockWallet.MockCreateHMAC = func(ctx context.Context, args wallet.CreateHMACArgs, originator string) (*wallet.CreateHMACResult, error) {
		return &wallet.CreateHMACResult{
			HMAC: tu.GetByte32FromString("test-hmac-value"),
		}, nil
	}

	// Set up CreateSignature response
	mockWallet.MockCreateSignature = func(ctx context.Context, args wallet.CreateSignatureArgs, originator string) (*wallet.CreateSignatureResult, error) {
		// Return a dummy signature result
		return &wallet.CreateSignatureResult{}, nil
	}

	// Set up VerifySignature response
	mockWallet.MockVerifySignature = func(ctx context.Context, args wallet.VerifySignatureArgs, originator string) (*wallet.VerifySignatureResult, error) {
		return &wallet.VerifySignatureResult{
			Valid: true,
		}, nil
	}

	// Set up ListCertificates response
	mockWallet.MockListCertificates = func(ctx context.Context, args wallet.ListCertificatesArgs, originator string) (*wallet.ListCertificatesResult, error) {
		return &wallet.ListCertificatesResult{
			Certificates: []wallet.CertificateResult{},
		}, nil
	}

	// Set up ProveCertificate response
	mockWallet.MockProveCertificate = func(ctx context.Context, args wallet.ProveCertificateArgs, originator string) (*wallet.ProveCertificateResult, error) {
		return &wallet.ProveCertificateResult{
			KeyringForVerifier: map[string]string{},
		}, nil
	}

	// Set up GetNetwork response
	mockWallet.MockGetNetwork = func(ctx context.Context, args any, originator string) (*wallet.GetNetworkResult, error) {
		return &wallet.GetNetworkResult{
			Network: "mainnet",
		}, nil
	}

	return mockWallet
}

func TestNewUploader(t *testing.T) {
	// Test with valid config
	mockWallet := wallet.NewMockWallet(t)
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
	assert.Error(t, err)
	assert.Nil(t, uploader)
	assert.Contains(t, err.Error(), "storage URL is required")

	// Test with nil wallet
	config = UploaderConfig{
		StorageURL: "https://example.com/storage",
		Wallet:     nil,
	}

	uploader, err = NewUploader(config)
	assert.Error(t, err)
	assert.Nil(t, uploader)
	assert.Contains(t, err.Error(), "wallet is required")
}

func TestStorageUploader_PublishFile(t *testing.T) {
	mockWallet := setupMockWalletForAuth(t)
	uploader, err := NewUploader(UploaderConfig{
		StorageURL: "https://example.com/storage",
		Wallet:     mockWallet,
	})
	require.NoError(t, err)
	assert.NotNil(t, uploader)
	assert.Equal(t, "https://example.com/storage", uploader.baseURL)
	assert.NotNil(t, uploader.authFetch)

	// Test file data
	testFile := UploadableFile{
		Data: []byte("test file content"),
		Type: "text/plain",
	}

	// This will fail due to network error since we're not connecting to a real server
	// But we can verify the uploader is properly configured
	_, err = uploader.PublishFile(context.Background(), testFile, 60)
	assert.Error(t, err) // Expected to fail due to network/auth issues

	// The error should be related to network/auth, not configuration
	assert.NotContains(t, err.Error(), "storage URL is required")
	assert.NotContains(t, err.Error(), "wallet is required")
}

func TestStorageUploader_FindFile(t *testing.T) {
	mockWallet := setupMockWalletForAuth(t)
	uploader, err := NewUploader(UploaderConfig{
		StorageURL: "https://example.com/storage",
		Wallet:     mockWallet,
	})
	require.NoError(t, err)
	assert.NotNil(t, uploader)

	// This will fail due to network error since we're not connecting to a real server
	// But we can verify the uploader is properly configured
	_, err = uploader.FindFile(context.Background(), "uhrp://test123")
	assert.Error(t, err) // Expected to fail due to network/auth issues

	// The error should be related to network/auth, not configuration
	assert.NotContains(t, err.Error(), "storage URL is required")
	assert.NotContains(t, err.Error(), "wallet is required")
}

// TestUploadFileResult tests the file upload result structure
func TestUploadFileResult(t *testing.T) {
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
	mockWallet := setupMockWalletForAuth(t)
	uploader, err := NewUploader(UploaderConfig{
		StorageURL: "https://example.com/storage",
		Wallet:     mockWallet,
	})
	require.NoError(t, err)

	// This will fail due to network error since we're not connecting to a real server
	// But we can verify the uploader is properly configured
	_, err = uploader.ListUploads(context.Background())
	assert.Error(t, err) // Expected to fail due to network/auth issues

	// The error should be related to network/auth, not configuration
	assert.NotContains(t, err.Error(), "storage URL is required")
	assert.NotContains(t, err.Error(), "wallet is required")
}

func TestStorageUploader_RenewFile(t *testing.T) {
	mockWallet := setupMockWalletForAuth(t)
	uploader, err := NewUploader(UploaderConfig{
		StorageURL: "https://example.com/storage",
		Wallet:     mockWallet,
	})
	require.NoError(t, err)

	// This will fail due to network error since we're not connecting to a real server
	// But we can verify the uploader is properly configured
	_, err = uploader.RenewFile(context.Background(), "uhrp://test123", 60)
	assert.Error(t, err) // Expected to fail due to network/auth issues

	// The error should be related to network/auth, not configuration
	assert.NotContains(t, err.Error(), "storage URL is required")
	assert.NotContains(t, err.Error(), "wallet is required")
}
