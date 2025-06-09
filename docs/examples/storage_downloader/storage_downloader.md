# Storage Downloader Example

This example demonstrates how to use the `storage` package to download files referenced by UHRP URLs.

## What is UHRP?

UHRP (Universal Hash Resolution Protocol) is a content-addressable storage system where files are identified by their hash. A UHRP URL follows the format `uhrp://{base58EncodedSHA256Hash}`, and can be resolved to find servers hosting the content.

## Example Overview

This example demonstrates:

1. Creating a `StorageDownloader` instance
2. Resolving a UHRP URL to find hosting servers 
3. Downloading file content
4. Saving the file locally
5. Using utility functions to work with UHRP URLs and file hashes

## Code Walkthrough

```go
// Create a new downloader with mainnet network preset
downloader := storage.NewStorageDownloader(storage.DownloaderConfig{
    Network: overlay.NetworkMainnet,
})
```

First, we create a new `StorageDownloader` instance configured to work with the mainnet network. The downloader is responsible for resolving and downloading content referenced by UHRP URLs.

```go
// Define the UHRP URL to download
uhrpURL := "uhrp://Tq71srNSBVHg69m3V8MeBy7YafjmYn21JDqc9iYaQSxmeSyGJ"

// First demonstrate resolving the URL to find hosting servers
hosts, err := downloader.Resolve(context.Background(), uhrpURL)
```

We use the `Resolve` method to find servers that are hosting the content. This method queries lookup services to determine which hosts have the file available for download.

```go
// Now download the file
result, err := downloader.Download(context.Background(), uhrpURL)
```

With the `Download` method, we retrieve the file content from the first available host. The method handles:
- Validating the UHRP URL
- Resolving hosting servers
- Trying each server until successful
- Verifying the content hash matches the expected hash in the URL
- Returning the content data and MIME type

```go
// Save the file with appropriate extension based on MIME type
outputFilename := "downloaded_file"
if result.MimeType != "" {
    // Append extension based on MIME type
    // ...
}
```

After downloading, we save the file with an extension based on its MIME type.

## Utility Functions

The example also demonstrates the utility functions available in the `storage` package:

```go
// Validate URL
fmt.Printf("Is valid URL: %v\n", storage.IsValidURL(uhrpURL))

// Extract hash from URL
hash, err := storage.GetHashFromURL(uhrpURL)

// Generate URL from file content
url, err := storage.GetURLForFile(result.Data)
```

These utility functions make it easy to:
- Validate UHRP URLs
- Extract the hash component from a UHRP URL
- Generate a UHRP URL from file content, which is useful when uploading files

## Running the Example

To run this example:

```bash
go run storage_downloader.go
```

**Note**: The example uses a specific UHRP URL for demonstration. If that URL is no longer available, replace it with a valid UHRP URL pointing to content you want to download.

## Error Handling

The example includes proper error handling for:
- Failed URL resolution
- Download failures
- Hash extraction errors
- File saving errors

This ensures that any issues encountered during the download process are appropriately reported to the user.

## Additional Resources

For more information on the storage package, see:
- [Package Documentation](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/storage)
- [Storage Uploader Example](../storage_uploader/) 