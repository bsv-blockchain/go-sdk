package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/storage"
)

func main() {
	// Create a new downloader with mainnet network preset
	downloader := storage.NewStorageDownloader(storage.DownloaderConfig{
		Network: overlay.NetworkMainnet,
	})

	// Define the UHRP URL to download
	// This is an example URL pointing to a test file
	uhrpURL := "uhrp://Tq71srNSBVHg69m3V8MeBy7YafjmYn21JDqc9iYaQSxmeSyGJ"

	// Now download the file
	fmt.Println("Downloading file...") //nolint:forbidigo // example program output
	result, err := downloader.Download(context.Background(), uhrpURL)
	if err != nil {
		log.Fatalf("Failed to download file: %v", err)
	}

	fmt.Printf("Successfully downloaded %d bytes\n", len(result.Data)) //nolint:forbidigo // example program output
	fmt.Printf("MIME type: %s\n", result.MimeType)                     //nolint:forbidigo // example program output

	// Save the file
	outputFilename := "downloaded_file"
	if result.MimeType != "" {
		// Append a simple extension based on MIME type
		switch result.MimeType {
		case "image/jpeg":
			outputFilename += ".jpg"
		case "image/png":
			outputFilename += ".png"
		case "text/plain":
			outputFilename += ".txt"
		case "application/json":
			outputFilename += ".json"
		case "application/pdf":
			outputFilename += ".pdf"
		}
	}

	if writeErr := os.WriteFile(outputFilename, result.Data, 0o600); writeErr != nil {
		log.Fatalf("Failed to save file: %v", writeErr)
	}

	fmt.Printf("File saved to: %s\n", outputFilename) //nolint:forbidigo // example program output

	// Demonstrate URL utility functions
	fmt.Println("\nUtility functions demonstration:") //nolint:forbidigo // example program output

	// Validate URL
	fmt.Printf("Is valid URL: %v\n", storage.IsValidURL(uhrpURL)) //nolint:forbidigo // example program output

	// Extract hash from URL
	hash, err := storage.GetHashFromURL(uhrpURL)
	if err != nil {
		fmt.Printf("Failed to extract hash: %v\n", err) //nolint:forbidigo // example program output
	} else {
		fmt.Printf("Extracted hash: %x\n", hash) //nolint:forbidigo // example program output
	}

	// Generate URL from file content
	url, err := storage.GetURLForFile(result.Data)
	if err != nil {
		fmt.Printf("Failed to generate URL: %v\n", err) //nolint:forbidigo // example program output
	} else {
		fmt.Printf("Generated URL from content: %s\n", url)      //nolint:forbidigo // example program output
		fmt.Printf("URL matches original: %v\n", url == uhrpURL) //nolint:forbidigo // example program output
	}
}
