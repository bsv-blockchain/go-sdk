package headers_client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/bsv-blockchain/go-sdk/v2/chainhash"
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

type Client struct {
	Ctx    context.Context
	Url    string
	ApiKey string
}

func (c Client) IsValidRootForHeight(root *chainhash.Hash, height uint32) (bool, error) {
	type requestBody struct {
		MerkleRoot  string `json:"merkleRoot"`
		BlockHeight uint32 `json:"blockHeight"`
	}

	payload := []requestBody{{MerkleRoot: root.String(), BlockHeight: height}}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("error marshaling JSON: %v", err)
	}

	req, err := http.NewRequest("POST", c.Url+"/api/v1/chain/merkleroot/verify", bytes.NewBuffer(jsonPayload))
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
		defer func() { _ = res.Body.Close() }()
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
		defer func() { _ = res.Body.Close() }()
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
		defer func() { _ = res.Body.Close() }()
		if err := json.NewDecoder(res.Body).Decode(headerState); err != nil {
			return nil, err
		}
	}
	return headerState, nil
}
