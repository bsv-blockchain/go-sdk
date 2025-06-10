// Package storage defines public interfaces and types for the storage SDK implementation.
package storage

import (
	"context"

	"github.com/bsv-blockchain/go-sdk/v2/overlay"
	"github.com/bsv-blockchain/go-sdk/v2/wallet"
)

// DownloaderConfig defines configuration options for StorageDownloader.
// Currently no additional configuration options are necessary beyond network preset.
type DownloaderConfig struct {
	Network overlay.Network // Network preset (Mainnet/Testnet/Local)
}

// DownloadResult is returned by StorageDownloader.Download.
type DownloadResult struct {
	Data     []byte // Raw file data
	MimeType string // MIME type of the downloaded content
}

// UploaderConfig defines configuration options for StorageUploader.
// StorageURL should point to the HTTP API base of the storage service.
// Wallet is used for authenticated endpoints for find, list, and renew operations.
type UploaderConfig struct {
	StorageURL string           // Base URL of the storage service
	Wallet     wallet.Interface // Wallet client for authenticated requests
}

// UploadableFile represents a file to be uploaded.
type UploadableFile struct {
	Data []byte // File content
	Type string // MIME type of the file
}

// UploadFileResult is returned by StorageUploader.PublishFile.
type UploadFileResult struct {
	UhrpURL   string // Generated UHRP URL for the uploaded file
	Published bool   // Indicates if the file was published successfully
}

// FindFileData is returned by StorageUploader.FindFile.
type FindFileData struct {
	Name       string // File name or path on the CDN
	Size       string // File size as returned by the service
	MimeType   string // MIME type of the file
	ExpiryTime int64  // Expiration timestamp
}

// UploadMetadata contains metadata for each upload returned by ListUploads.
type UploadMetadata struct {
	UhrpURL    string // UHRP URL of the file
	ExpiryTime int64  // Expiration timestamp
}

// RenewFileResult is returned by StorageUploader.RenewFile.
type RenewFileResult struct {
	Status         string // Status returned by the service (e.g., "success")
	PrevExpiryTime int64  // Previous expiration timestamp
	NewExpiryTime  int64  // New expiration timestamp
	Amount         int64  // Amount charged or refilled
}

// StorageDownloaderInterface defines the public API for downloading files
type StorageDownloaderInterface interface {
	// Resolve returns a list of HTTP URLs for a given UHRP URL
	Resolve(ctx context.Context, uhrpURL string) ([]string, error)

	// Download retrieves a file from the first available host
	Download(ctx context.Context, uhrpURL string) (DownloadResult, error)
}

// StorageUploaderInterface defines the public API for uploading and managing files
type StorageUploaderInterface interface {
	// PublishFile uploads a file to the storage service with the specified retention period
	PublishFile(ctx context.Context, file UploadableFile, retentionPeriod int) (UploadFileResult, error)

	// FindFile retrieves metadata for a file matching the given UHRP URL
	FindFile(ctx context.Context, uhrpURL string) (FindFileData, error)

	// ListUploads lists all advertisements belonging to the user
	ListUploads(ctx context.Context) (interface{}, error)

	// RenewFile extends the hosting time for an existing file advertisement
	RenewFile(ctx context.Context, uhrpURL string, additionalMinutes int) (RenewFileResult, error)
}
