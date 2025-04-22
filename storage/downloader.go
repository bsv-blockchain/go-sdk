// Package storage implements the storage downloader functionality.
package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/util"
)

// StorageDownloader handles resolving and downloading files via UHRP URLs.
type StorageDownloader struct {
	resolver *lookup.LookupResolver
}

// NewStorageDownloader creates a new StorageDownloader with the given config.
func NewStorageDownloader(cfg DownloaderConfig) *StorageDownloader {
	resolver := lookup.NewLookupResolver(&lookup.LookupResolver{
		NetworkPreset: cfg.Network,
	})
	return &StorageDownloader{resolver: resolver}
}

// Resolve fetches host URLs for the given UHRP URL by querying lookup services.
func (d *StorageDownloader) Resolve(ctx context.Context, uhrpURL string) ([]string, error) {
	// Create a lookup question
	queryData, err := json.Marshal(map[string]string{"uhrpUrl": uhrpURL})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	q := &lookup.LookupQuestion{
		Service: "ls_uhrp",
		Query:   queryData,
	}

	// Set a timeout for the lookup
	ctxWithTimeout, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	// Query the lookup service
	ans, err := d.resolver.Query(ctxWithTimeout, q, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UHRP URL: %w", err)
	}

	// Check answer type
	if ans.Type != lookup.AnswerTypeOutputList {
		return nil, errors.New("lookup answer must be an output list")
	}

	// Process each output
	hosts := make([]string, 0)
	currentTime := time.Now().Unix()

	for _, output := range ans.Outputs {
		tx, err := transaction.NewTransactionFromBEEF(output.Beef)
		if err != nil {
			continue
		}

		if int(output.OutputIndex) >= len(tx.Outputs) {
			continue
		}

		pd := pushdrop.Decode(tx.Outputs[output.OutputIndex].LockingScript)
		if pd == nil || len(pd.Fields) < 4 {
			continue
		}

		// Check expiry time (field 3)
		expiryReader := util.NewReader(pd.Fields[3])
		expiryTime, err := expiryReader.ReadVarInt()
		if err != nil || int64(expiryTime) < currentTime {
			continue
		}

		// Add host URL (field 2) to results if it's a valid string
		if len(pd.Fields) > 2 {
			hostURL := string(pd.Fields[2])
			if hostURL != "" {
				hosts = append(hosts, hostURL)
			}
		}
	}

	return hosts, nil
}

// Download retrieves the file from the first available host matching the UHRP URL hash.
func (d *StorageDownloader) Download(ctx context.Context, uhrpURL string) (DownloadResult, error) {
	// Validate URL
	if !IsValidURL(uhrpURL) {
		return DownloadResult{}, errors.New("invalid parameter UHRP url")
	}

	// Get hash from URL
	hash, err := GetHashFromURL(uhrpURL)
	if err != nil {
		return DownloadResult{}, err
	}

	// Resolve hosts
	hosts, err := d.Resolve(ctx, uhrpURL)
	if err != nil {
		return DownloadResult{}, err
	}

	if len(hosts) == 0 {
		return DownloadResult{}, errors.New("no one currently hosts this file")
	}

	// Try each host
	client := &http.Client{
		Timeout: time.Second * 30,
	}

	var lastErr error
	for _, host := range hosts {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, host, nil)
		if err != nil {
			lastErr = err
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode >= 400 {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d from %s", resp.StatusCode, host)
			continue
		}

		// Read response body
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if err != nil {
			lastErr = fmt.Errorf("error reading response body: %w", err)
			continue
		}

		// Verify hash
		contentHash := crypto.Sha256(body)
		if !bytes.Equal(contentHash, hash) {
			lastErr = fmt.Errorf("content hash mismatch from %s", host)
			continue
		}

		// Success
		return DownloadResult{
			Data:     body,
			MimeType: resp.Header.Get("Content-Type"),
		}, nil
	}

	// If we got here, all hosts failed
	if lastErr != nil {
		return DownloadResult{}, fmt.Errorf("unable to download content: %w", lastErr)
	}
	return DownloadResult{}, fmt.Errorf("unable to download content from %s", uhrpURL)
}
