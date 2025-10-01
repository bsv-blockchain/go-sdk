// Package storage provides decentralized file storage capabilities with UHRP (Universal Hash Resolution Protocol)
// URL support. It enables uploading files to distributed storage networks, downloading from multiple hosts,
// managing file metadata, and handling retention periods. The package integrates with wallet authentication
// for secure operations and supports various MIME types and file formats.
package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	authhttp "github.com/bsv-blockchain/go-sdk/auth/clients/authhttp"
)

// API response status constants
const (
	StatusSuccess = "success"
	StatusError   = "error"
)

// checkAPIError is a common function to handle API error responses
func checkAPIError(status, code, description, operation string) error {
	if status == StatusError {
		errCode := code
		if errCode == "" {
			errCode = "unknown-code"
		}
		errDesc := description
		if errDesc == "" {
			errDesc = "no-description"
		}
		return fmt.Errorf("%s returned an error: %s - %s", operation, errCode, errDesc)
	}
	return nil
}

// Uploader implements the StorageUploaderInterface
type Uploader struct {
	baseURL   string              // Base URL of the storage service
	authFetch *authhttp.AuthFetch // Authenticated HTTP client for API requests
}

// NewUploader creates a new uploader instance
func NewUploader(config UploaderConfig) (*Uploader, error) {
	if config.StorageURL == "" {
		return nil, errors.New("storage URL is required")
	}
	if config.Wallet == nil {
		return nil, errors.New("wallet is required for authentication")
	}

	// Create auth fetch client
	authClient := authhttp.New(config.Wallet)

	return &Uploader{
		baseURL:   config.StorageURL,
		authFetch: authClient,
	}, nil
}

// uploadInfo is used to parse the response from the /upload endpoint
type uploadInfo struct {
	Status          string            `json:"status"`
	UploadURL       string            `json:"uploadURL"`
	RequiredHeaders map[string]string `json:"requiredHeaders"`
	Amount          *int64            `json:"amount,omitempty"`
}

// getUploadInfo requests information from the server to upload a file
func (u *Uploader) getUploadInfo(ctx context.Context, fileSize int, retentionPeriod int) (*uploadInfo, error) {
	uploadUrl := fmt.Sprintf("%s/upload", u.baseURL)
	requestBody := map[string]interface{}{
		"fileSize":        fileSize,
		"retentionPeriod": retentionPeriod,
	}

	requestJSON, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	reqOpts := &authhttp.SimplifiedFetchRequestOptions{
		Method: "POST",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: requestJSON,
	}

	resp, err := u.authFetch.Fetch(ctx, uploadUrl, reqOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to get upload info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upload info request failed: HTTP %d", resp.StatusCode)
	}

	var info uploadInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode upload info response: %w", err)
	}

	if info.Status == StatusError {
		return nil, errors.New("upload route returned an error")
	}

	return &info, nil
}

// uploadFile performs the file upload to the presigned URL
func (u *Uploader) uploadFile(ctx context.Context, uploadURL string, file UploadableFile, requiredHeaders map[string]string) (UploadFileResult, error) {
	// Create HTTP client
	client := &http.Client{}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "PUT", uploadURL, bytes.NewReader(file.Data))
	if err != nil {
		return UploadFileResult{}, fmt.Errorf("failed to create upload request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", file.Type)
	for key, value := range requiredHeaders {
		req.Header.Set(key, value)
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return UploadFileResult{}, fmt.Errorf("file upload failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return UploadFileResult{}, fmt.Errorf("file upload failed: HTTP %d - %s", resp.StatusCode, string(bodyBytes))
	}

	// Generate UHRP URL for the uploaded file
	uhrpURL, err := GetURLForFile(file.Data)
	if err != nil {
		return UploadFileResult{}, fmt.Errorf("failed to generate UHRP URL: %w", err)
	}

	return UploadFileResult{
		Published: true,
		UhrpURL:   uhrpURL,
	}, nil
}

// PublishFile uploads a file to the storage service with the specified retention period
// It follows a two-step process:
// 1. Request an upload URL from the server
// 2. Upload the file to the provided URL
func (u *Uploader) PublishFile(ctx context.Context, file UploadableFile, retentionPeriod int) (UploadFileResult, error) {
	fileSize := len(file.Data)

	// Step 1: Get upload info from server
	uploadInfo, err := u.getUploadInfo(ctx, fileSize, retentionPeriod)
	if err != nil {
		return UploadFileResult{}, err
	}

	// Step 2: Upload file to presigned URL
	return u.uploadFile(ctx, uploadInfo.UploadURL, file, uploadInfo.RequiredHeaders)
}

// FindFile retrieves metadata for a file matching the given UHRP URL
func (u *Uploader) FindFile(ctx context.Context, uhrpURL string) (FindFileData, error) {
	// Build the URL with the uhrpURL as a query parameter
	findURL, err := url.Parse(fmt.Sprintf("%s/find", u.baseURL))
	if err != nil {
		return FindFileData{}, fmt.Errorf("failed to parse find URL: %w", err)
	}

	query := findURL.Query()
	query.Set("uhrpUrl", uhrpURL)
	findURL.RawQuery = query.Encode()

	// Make authenticated request
	reqOpts := &authhttp.SimplifiedFetchRequestOptions{
		Method: "GET",
	}

	resp, err := u.authFetch.Fetch(ctx, findURL.String(), reqOpts)
	if err != nil {
		return FindFileData{}, fmt.Errorf("findFile request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return FindFileData{}, fmt.Errorf("findFile request failed: HTTP %d", resp.StatusCode)
	}

	// Parse response
	var response struct {
		Status      string       `json:"status"`
		Data        FindFileData `json:"data"`
		Code        string       `json:"code,omitempty"`
		Description string       `json:"description,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return FindFileData{}, fmt.Errorf("failed to decode findFile response: %w", err)
	}

	// Check for errors in the response
	if err := checkAPIError(response.Status, response.Code, response.Description, "findFile"); err != nil {
		return FindFileData{}, err
	}

	return response.Data, nil
}

// ListUploads lists all advertisements belonging to the user
func (u *Uploader) ListUploads(ctx context.Context) (interface{}, error) {
	uploadUrl := fmt.Sprintf("%s/list", u.baseURL)

	// Make authenticated request
	reqOpts := &authhttp.SimplifiedFetchRequestOptions{
		Method: "GET",
	}

	resp, err := u.authFetch.Fetch(ctx, uploadUrl, reqOpts)
	if err != nil {
		return nil, fmt.Errorf("listUploads request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("listUploads request failed: HTTP %d", resp.StatusCode)
	}

	// Parse response
	var response struct {
		Status      string      `json:"status"`
		Uploads     interface{} `json:"uploads"`
		Code        string      `json:"code,omitempty"`
		Description string      `json:"description,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode listUploads response: %w", err)
	}

	// Check for errors in the response
	if err := checkAPIError(response.Status, response.Code, response.Description, "listUploads"); err != nil {
		return nil, err
	}

	return response.Uploads, nil
}

// RenewFile extends the hosting time for an existing file advertisement
func (u *Uploader) RenewFile(ctx context.Context, uhrpURL string, additionalMinutes int) (RenewFileResult, error) {
	uploadUrl := fmt.Sprintf("%s/renew", u.baseURL)
	requestBody := map[string]interface{}{
		"uhrpUrl":           uhrpURL,
		"additionalMinutes": additionalMinutes,
	}

	requestJSON, err := json.Marshal(requestBody)
	if err != nil {
		return RenewFileResult{}, fmt.Errorf("failed to marshal request body: %w", err)
	}

	reqOpts := &authhttp.SimplifiedFetchRequestOptions{
		Method: "POST",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: requestJSON,
	}

	resp, err := u.authFetch.Fetch(ctx, uploadUrl, reqOpts)
	if err != nil {
		return RenewFileResult{}, fmt.Errorf("renewFile request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return RenewFileResult{}, fmt.Errorf("renewFile request failed: HTTP %d", resp.StatusCode)
	}

	// Parse response
	var response struct {
		Status         string `json:"status"`
		PrevExpiryTime *int64 `json:"prevExpiryTime,omitempty"`
		NewExpiryTime  *int64 `json:"newExpiryTime,omitempty"`
		Amount         *int64 `json:"amount,omitempty"`
		Code           string `json:"code,omitempty"`
		Description    string `json:"description,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return RenewFileResult{}, fmt.Errorf("failed to decode renewFile response: %w", err)
	}

	// Check for errors in the response
	if err := checkAPIError(response.Status, response.Code, response.Description, "renewFile"); err != nil {
		return RenewFileResult{}, err
	}

	// Convert pointer fields to required types for the result structure
	var prevExpiry, newExpiry, amount int64
	if response.PrevExpiryTime != nil {
		prevExpiry = *response.PrevExpiryTime
	}
	if response.NewExpiryTime != nil {
		newExpiry = *response.NewExpiryTime
	}
	if response.Amount != nil {
		amount = *response.Amount
	}

	return RenewFileResult{
		Status:         response.Status,
		PrevExpiryTime: prevExpiry,
		NewExpiryTime:  newExpiry,
		Amount:         amount,
	}, nil
}
