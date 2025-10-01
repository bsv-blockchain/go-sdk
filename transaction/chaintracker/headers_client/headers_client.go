package headers_client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/bsv-blockchain/go-sdk/chainhash"
)

type Header struct {
	Height        uint32         `json:"height"`
	Hash          chainhash.Hash `json:"hash"`
	Version       uint32         `json:"version"`
	MerkleRoot    chainhash.Hash `json:"merkleRoot"`
	Timestamp     uint32         `json:"creationTimestamp"`
	Bits          uint32         `json:"difficultyTarget"`
	Nonce         uint32         `json:"nonce"`
	PreviousBlock chainhash.Hash `json:"prevBlockHash"`
}

type State struct {
	Header Header `json:"header"`
	State  string `json:"state"`
	Height uint32 `json:"height"`
}

type MerkleRootInfo struct {
	MerkleRoot  chainhash.Hash `json:"merkleRoot"`
	BlockHeight int32          `json:"blockHeight"`
}

type Client struct {
	Ctx    context.Context
	Url    string
	ApiKey string
}

func (c Client) IsValidRootForHeight(ctx context.Context, root *chainhash.Hash, height uint32) (bool, error) {
	type requestBody struct {
		MerkleRoot  string `json:"merkleRoot"`
		BlockHeight uint32 `json:"blockHeight"`
	}

	payload := []requestBody{{MerkleRoot: root.String(), BlockHeight: height}}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("error marshaling JSON: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.Url+"/api/v1/chain/merkleroot/verify", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return false, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.ApiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

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

func (c *Client) BlockByHeight(ctx context.Context, height uint32) (*Header, error) {
	headers := []Header{}
	client := &http.Client{}
	url := fmt.Sprintf("%s/api/v1/chain/header/byHeight?height=%d", c.Url, height)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.ApiKey)
	if res, err := client.Do(req); err != nil {
		return nil, err
	} else {
		defer res.Body.Close()
		if err := json.NewDecoder(res.Body).Decode(&headers); err != nil {
			return nil, err
		}
		for _, header := range headers {
			if state, err := c.GetBlockState(ctx, header.Hash.String()); err != nil {
				return nil, err
			} else if state.State == "LONGEST_CHAIN" {
				header.Height = state.Height
				return &header, nil
			}
		}
		// Check if headers array is empty before accessing
		if len(headers) == 0 {
			return nil, fmt.Errorf("no block headers found for height %d", height)
		}
		header := &headers[0]
		header.Height = height
		return header, nil
	}
}

func (c *Client) GetBlockState(ctx context.Context, hash string) (*State, error) {
	headerState := &State{}
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/chain/header/state/%s", c.Url, hash), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.ApiKey)
	if res, err := client.Do(req); err != nil {
		return nil, err
	} else {
		defer res.Body.Close()
		if err := json.NewDecoder(res.Body).Decode(headerState); err != nil {
			return nil, err
		}
	}
	return headerState, nil
}

func (c *Client) GetChaintip(ctx context.Context) (*State, error) {
	headerState := &State{}
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/chain/tip/longest", c.Url), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.ApiKey)
	if res, err := client.Do(req); err != nil {
		return nil, err
	} else {
		defer res.Body.Close()
		if err := json.NewDecoder(res.Body).Decode(headerState); err != nil {
			return nil, err
		}
	}
	return headerState, nil
}

func (c *Client) CurrentHeight(ctx context.Context) (uint32, error) {
	tip, err := c.GetChaintip(ctx)
	if err != nil {
		return 0, err
	}
	return tip.Height, nil
}

// GetMerkleRoots fetches merkle roots in bulk from the block-headers-service
func (c *Client) GetMerkleRoots(ctx context.Context, batchSize int, lastEvaluatedKey *chainhash.Hash) ([]MerkleRootInfo, error) {
	client := &http.Client{}

	// Build URL with query parameters
	url := fmt.Sprintf("%s/api/v1/chain/merkleroot?batchSize=%d", c.Url, batchSize)
	if lastEvaluatedKey != nil {
		url += fmt.Sprintf("&lastEvaluatedKey=%s", lastEvaluatedKey.String())
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.ApiKey)

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	// Parse the paged response
	var response struct {
		Content []MerkleRootInfo `json:"content"`
		Page    struct {
			LastEvaluatedKey string `json:"lastEvaluatedKey"`
		} `json:"page"`
	}

	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, err
	}

	return response.Content, nil
}

// WebhookRequest represents a webhook registration request
type WebhookRequest struct {
	URL          string       `json:"url"`
	RequiredAuth RequiredAuth `json:"requiredAuth"`
}

// RequiredAuth defines auth information for webhook registration
type RequiredAuth struct {
	Type   string `json:"type"`   // e.g., "Bearer"
	Token  string `json:"token"`  // The auth token
	Header string `json:"header"` // e.g., "Authorization"
}

// Webhook represents a registered webhook
type Webhook struct {
	URL               string `json:"url"`
	CreatedAt         string `json:"createdAt"`
	LastEmitStatus    string `json:"lastEmitStatus"`
	LastEmitTimestamp string `json:"lastEmitTimestamp"`
	ErrorsCount       int    `json:"errorsCount"`
	Active            bool   `json:"active"`
}

// RegisterWebhook registers a webhook URL with the block headers service
func (c *Client) RegisterWebhook(ctx context.Context, callbackURL string, authToken string) (*Webhook, error) {
	req := WebhookRequest{
		URL: callbackURL,
		RequiredAuth: RequiredAuth{
			Type:   "Bearer",
			Token:  authToken,
			Header: "Authorization",
		},
	}

	jsonPayload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("error marshaling webhook request: %v", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.Url+"/api/v1/webhook", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.ApiKey)

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to register webhook: status=%d, body=%s", resp.StatusCode, body)
	}

	var webhook Webhook
	if err := json.NewDecoder(resp.Body).Decode(&webhook); err != nil {
		return nil, fmt.Errorf("error decoding response: %v", err)
	}

	return &webhook, nil
}

// UnregisterWebhook removes a webhook URL from the block headers service
func (c *Client) UnregisterWebhook(ctx context.Context, callbackURL string) error {
	httpReq, err := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("%s/api/v1/webhook?url=%s", c.Url, callbackURL), nil)
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+c.ApiKey)

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to unregister webhook: status=%d, body=%s", resp.StatusCode, body)
	}

	return nil
}

// GetWebhook retrieves a webhook by URL from the block headers service
func (c *Client) GetWebhook(ctx context.Context, callbackURL string) (*Webhook, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/api/v1/webhook?url=%s", c.Url, callbackURL), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+c.ApiKey)

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get webhook: status=%d, body=%s", resp.StatusCode, body)
	}

	var webhook Webhook
	if err := json.NewDecoder(resp.Body).Decode(&webhook); err != nil {
		return nil, fmt.Errorf("error decoding response: %v", err)
	}

	return &webhook, nil
}
