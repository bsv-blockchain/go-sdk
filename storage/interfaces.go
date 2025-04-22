// Package storage defines public interfaces and types for the storage SDK implementation.
package storage

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// DownloaderConfig defines configuration options for StorageDownloader.
// Currently no configuration options are necessary, but this struct is provided for future extensibility.
type DownloaderConfig struct{}

// DownloadResult is returned by StorageDownloader.Download.
type DownloadResult struct {
	Data     []byte // Raw file data
	MimeType string // MIME type of the downloaded content
}

// UploaderConfig defines configuration options for StorageUploader.
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
