package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Example extending interface transaction/chaintracker/chaintracker.go

// BlockHeadersClient represents a Block Headers Client.
type BlockHeadersClient struct {
	URL    string
	APIKey string
}

// NewBlockHeadersClient constructs an instance of the BlockHeadersClient.
func NewBlockHeadersClient(URL string, APIKey string) *BlockHeadersClient {
	return &BlockHeadersClient{
		URL:    URL,
		APIKey: APIKey,
	}
}

// IsValidRootForHeight checks a set of merkle roots with corresponding heights.
func (b *BlockHeadersClient) IsValidRootForHeight(root []byte, height uint32) (bool, error) {
	type requestBody struct {
		MerkleRoot  string `json:"merkleRoot"`
		BlockHeight uint32 `json:"blockHeight"`
	}

	payload := []requestBody{{MerkleRoot: hex.EncodeToString(root), BlockHeight: height}}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("error marshaling JSON: %v", err)
	}

	req, err := http.NewRequest("POST", b.URL+"/api/v1/chain/merkleroot/verify", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return false, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+b.APIKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("error sending request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("error reading response body: %v", err)
	}

	var response struct {
		ConfirmationState string `json:"confirmationState"`
	}

	err = json.Unmarshal(body, &response)
	if err != nil {
		return false, fmt.Errorf("error unmarshaling JSON: %v", err)
	}

	return response.ConfirmationState == "CONFIRMED", nil
}
