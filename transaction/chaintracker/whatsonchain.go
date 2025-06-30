package chaintracker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bsv-blockchain/go-sdk/chainhash"
)

type Network string

type BlockHeader struct {
	Hash       *chainhash.Hash `json:"hash"`
	Height     uint32          `json:"height"`
	Version    uint32          `json:"version"`
	MerkleRoot *chainhash.Hash `json:"merkleroot"`
	Time       uint32          `json:"time"`
	Nonce      uint32          `json:"nonce"`
	Bits       string          `json:"bits"`
	PrevHash   *chainhash.Hash `json:"previousblockhash"`
}

var (
	MainNet Network = "main"
	TestNet Network = "test"
)

type WhatsOnChain struct {
	Network Network
	ApiKey  string
	baseURL string
	client  *http.Client
}

func NewWhatsOnChain(network Network, apiKey string) *WhatsOnChain {
	return &WhatsOnChain{
		Network: network,
		ApiKey:  apiKey,
		baseURL: fmt.Sprintf("https://api.whatsonchain.com/v1/bsv/%s", network),
		client:  http.DefaultClient,
	}
}

// GetBlockHeader retrieves the block header for a given height
func (w *WhatsOnChain) GetBlockHeader(ctx context.Context, height uint32) (header *BlockHeader, err error) {
	url := fmt.Sprintf("%s/block/%d/header", w.baseURL, height)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", w.ApiKey)

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to verify merkleroot for height %d: %v", height, resp.Status)
	}

	header = &BlockHeader{}
	if err := json.NewDecoder(resp.Body).Decode(header); err != nil {
		return nil, err
	}

	return header, nil
}

func (w *WhatsOnChain) IsValidRootForHeight(ctx context.Context, root *chainhash.Hash, height uint32) (bool, error) {
	if header, err := w.GetBlockHeader(ctx, height); err != nil {
		return false, err
	} else {
		return header.MerkleRoot.IsEqual(root), nil
	}
}
