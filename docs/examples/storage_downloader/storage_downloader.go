package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/bsv-blockchain/go-sdk/v2/overlay"
	"github.com/bsv-blockchain/go-sdk/v2/storage"
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
	fmt.Println("Downloading file...")
	result, err := downloader.Download(context.Background(), uhrpURL)
	if err != nil {
		log.Fatalf("Failed to download file: %v", err)
	}

	fmt.Printf("Successfully downloaded %d bytes\n", len(result.Data))
	fmt.Printf("MIME type: %s\n", result.MimeType)

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

	if err := os.WriteFile(outputFilename, result.Data, 0644); err != nil {
		log.Fatalf("Failed to save file: %v", err)
	}

	fmt.Printf("File saved to: %s\n", outputFilename)

	// Demonstrate URL utility functions
	fmt.Println("\nUtility functions demonstration:")

	// Validate URL
	fmt.Printf("Is valid URL: %v\n", storage.IsValidURL(uhrpURL))

	// Extract hash from URL
	hash, err := storage.GetHashFromURL(uhrpURL)
	if err != nil {
		fmt.Printf("Failed to extract hash: %v\n", err)
	} else {
		fmt.Printf("Extracted hash: %x\n", hash)
	}

	// Generate URL from file content
	url, err := storage.GetURLForFile(result.Data)
	if err != nil {
		fmt.Printf("Failed to generate URL: %v\n", err)
	} else {
		fmt.Printf("Generated URL from content: %s\n", url)
		fmt.Printf("URL matches original: %v\n", url == uhrpURL)
	}
}
