package headers_client

import (
	"context"
	"encoding/json"
	"fmt"
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
