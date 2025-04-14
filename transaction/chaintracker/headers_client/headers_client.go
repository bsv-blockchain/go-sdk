package headers_client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

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

type Client struct {
	Ctx    context.Context
	Url    string
	ApiKey string
}

func (c Client) IsValidRootForHeight(root *chainhash.Hash, height uint32) (bool, error) {
	if header, err := c.BlockByHeight(c.Ctx, height); err != nil {
		return false, err
	} else {
		return header.MerkleRoot.Equal(*root), nil
	}
}

func (c *Client) BlockByHeight(ctx context.Context, height uint32) (*Header, error) {
	headers := []Header{}
	client := &http.Client{}

	// Parse the base URL
	baseURL, err := url.Parse(c.Url)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Construct the path
	baseURL.Path = baseURL.ResolveReference(&url.URL{Path: "api/v1/chain/header/byHeight"}).Path

	// Add query parameters
	q := baseURL.Query()
	q.Add("height", strconv.FormatUint(uint64(height), 10))
	baseURL.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", baseURL.String(), nil)
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
		header := &headers[0]
		header.Height = height
		return header, nil
	}
}

func (c *Client) GetBlockState(ctx context.Context, hash string) (*State, error) {
	headerState := &State{}
	client := &http.Client{}

	// Parse the base URL
	baseURL, err := url.Parse(c.Url)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Construct the path with the hash
	path := fmt.Sprintf("api/v1/chain/header/state/%s", hash)
	baseURL.Path = baseURL.ResolveReference(&url.URL{Path: path}).Path

	req, err := http.NewRequest("GET", baseURL.String(), nil)
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
