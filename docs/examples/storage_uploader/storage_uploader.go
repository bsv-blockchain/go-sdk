package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/bsv-blockchain/go-sdk/storage"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// For demonstration purposes. In a real application, you would use
// a proper wallet implementation.
type MockWallet struct {
	wallet.Interface
}

func main() {
	// Get sample content to upload
	// In this example, we'll create a simple text file
	content := []byte("This is a sample file uploaded using the Storage package.")

	// Set up the uploader with a storage service URL and wallet
	uploader, err := storage.NewUploader(storage.UploaderConfig{
		StorageURL: "https://storage-api.bsv.com",
		Wallet:     &MockWallet{}, // This is a mock wallet for the example
	})
	if err != nil {
		log.Fatalf("Failed to create uploader: %v", err)
	}

	// Prepare the file for upload
	file := storage.UploadableFile{
		Data: content,
		Type: "text/plain", // MIME type
	}

	fmt.Println("Uploading file...") //nolint:forbidigo // example program output
	// Upload the file with a 60-minute retention period
	result, err := uploader.PublishFile(context.Background(), file, 60)
	if err != nil {
		log.Fatalf("Failed to upload file: %v", err)
	}

	if result.Published {
		fmt.Printf("File successfully published!\n") //nolint:forbidigo // example program output
		fmt.Printf("UHRP URL: %s\n", result.UhrpURL) //nolint:forbidigo // example program output
	} else {
		fmt.Println("File publication was not successful.") //nolint:forbidigo // example program output
		return
	}

	// Find information about the uploaded file
	fmt.Println("\nRetrieving file metadata...") //nolint:forbidigo // example program output
	fileData, err := uploader.FindFile(context.Background(), result.UhrpURL)
	if err != nil {
		log.Fatalf("Failed to find file: %v", err)
	}

	fmt.Printf("File name: %s\n", fileData.Name)                                            //nolint:forbidigo // example program output
	fmt.Printf("File size: %s\n", fileData.Size)                                            //nolint:forbidigo // example program output
	fmt.Printf("MIME type: %s\n", fileData.MimeType)                                        //nolint:forbidigo // example program output
	fmt.Printf("Expiry time: %s\n", time.Unix(fileData.ExpiryTime, 0).Format(time.RFC3339)) //nolint:forbidigo // example program output

	// List all uploads for the current user
	fmt.Println("\nListing all uploads...") //nolint:forbidigo // example program output
	uploads, err := uploader.ListUploads(context.Background())
	if err != nil {
		log.Fatalf("Failed to list uploads: %v", err)
	}

	// Type assertion to get the correct type for the uploads
	uploadsList, ok := uploads.([]storage.UploadMetadata)
	if !ok {
		fmt.Println("Unexpected type for uploads list") //nolint:forbidigo // example program output
	} else {
		fmt.Printf("Found %d uploads:\n", len(uploadsList)) //nolint:forbidigo // example program output
		for i, upload := range uploadsList {
			fmt.Printf( //nolint:forbidigo // example program output
				"  %d. %s (expires: %s)\n",
				i+1,
				upload.UhrpURL,
				time.Unix(upload.ExpiryTime, 0).Format(time.RFC3339),
			)
		}
	}

	// Renew the file for an additional 30 minutes
	fmt.Println("\nRenewing file for an additional 30 minutes...") //nolint:forbidigo // example program output
	renewResult, err := uploader.RenewFile(context.Background(), result.UhrpURL, 30)
	if err != nil {
		log.Fatalf("Failed to renew file: %v", err)
	}

	fmt.Printf("Previous expiry: %s\n", //nolint:forbidigo // example program output
		time.Unix(renewResult.PrevExpiryTime, 0).Format(time.RFC3339))
	fmt.Printf("New expiry: %s\n", //nolint:forbidigo // example program output
		time.Unix(renewResult.NewExpiryTime, 0).Format(time.RFC3339))
	fmt.Printf("Amount charged: %d\n", renewResult.Amount) //nolint:forbidigo // example program output

	// Demonstrate generating a UHRP URL from file content
	// This should match the URL returned from the upload
	fmt.Println("\nDemonstrating URL generation from content...") //nolint:forbidigo // example program output
	generatedURL, err := storage.GetURLForFile(content)
	if err != nil {
		log.Fatalf("Failed to generate URL: %v", err)
	}

	fmt.Printf("Generated URL: %s\n", generatedURL)                        //nolint:forbidigo // example program output
	fmt.Printf("Matches upload URL: %v\n", generatedURL == result.UhrpURL) //nolint:forbidigo // example program output

	fmt.Println("\nStorage operations complete!") //nolint:forbidigo // example program output
}
