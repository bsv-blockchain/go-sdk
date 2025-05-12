# Storage Uploader Example

This example demonstrates how to use the `storage` package to upload, manage, and renew files using the storage service API.

## Overview

The storage uploader provides functionality to:
1. Upload files to the storage service
2. Retrieve metadata about uploaded files
3. List all files uploaded by the user
4. Renew file hosting for extended periods

## Authentication

All uploader operations require authentication. The uploader uses the provided wallet implementation to sign requests to the storage service. In a real application, you would implement a complete wallet that satisfies the `wallet.Interface` requirements.

## Example Overview

This example demonstrates:

1. Creating a `StorageUploader` instance
2. Uploading a file
3. Retrieving file metadata
4. Listing all user uploads
5. Renewing file hosting
6. Generating a UHRP URL from file content

## Code Walkthrough

### Setting Up the Uploader

```go
uploader, err := storage.NewStorageUploader(storage.UploaderConfig{
    StorageURL: "https://storage-api.bsv.com",
    Wallet:     &MockWallet{}, // This is a mock wallet for the example
})
```

First, we create a new `StorageUploader` instance configured with the storage service URL and a wallet implementation for authentication.

### Uploading a File

```go
file := storage.UploadableFile{
    Data: content,
    Type: "text/plain", // MIME type
}

result, err := uploader.PublishFile(context.Background(), file, 60)
```

The `PublishFile` method uploads a file to the storage service with a specified retention period (in minutes). It returns a result containing the UHRP URL for the uploaded file.

### Retrieving File Metadata

```go
fileData, err := uploader.FindFile(context.Background(), result.UhrpURL)
```

Using the `FindFile` method, we retrieve metadata about a previously uploaded file, including its name, size, MIME type, and expiration time.

### Listing User Uploads

```go
uploads, err := uploader.ListUploads(context.Background())
```

The `ListUploads` method returns a list of all files the user has uploaded, including their UHRP URLs and expiration times.

### Renewing File Hosting

```go
renewResult, err := uploader.RenewFile(context.Background(), result.UhrpURL, 30)
```

With the `RenewFile` method, we extend the hosting period for a file by a specified number of minutes. The method returns the previous and new expiration times, along with the amount charged for the renewal.

### URL Generation

```go
generatedURL, err := storage.GetURLForFile(content)
```

Finally, we demonstrate how to generate a UHRP URL directly from file content. This is useful for verifying that the URL generated locally matches the one returned by the storage service after upload.

## Running the Example

To run this example:

```bash
go run storage_uploader.go
```

**Note**: This example uses a mock wallet and will not successfully connect to the storage service without a proper wallet implementation. The code is provided as a reference for the required API calls and data structures.

## Integration Steps

To integrate the storage uploader in your application:

1. Implement the `wallet.Interface` to provide authentication
2. Configure the uploader with your storage service endpoint
3. Use the appropriate methods based on your needs:
   - `PublishFile` for uploading new files
   - `FindFile` for retrieving file metadata
   - `ListUploads` for viewing all user uploads
   - `RenewFile` for extending hosting periods

## Common Operations

| Operation | Method | Description |
|-----------|--------|-------------|
| Upload File | `PublishFile` | Uploads a file with a specified retention period |
| Get Metadata | `FindFile` | Retrieves metadata for a specific file |
| List Files | `ListUploads` | Lists all files uploaded by the user |
| Extend Hosting | `RenewFile` | Extends the hosting period for a file |

## Additional Resources

For more information on the storage package, see:
- [Package Documentation](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/storage)
- [Storage Downloader Example](../storage_downloader/) 