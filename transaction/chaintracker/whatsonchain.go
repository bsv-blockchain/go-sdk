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

type ChainInfo struct {
	Blocks uint32 `json:"blocks"`
}

func NewWhatsOnChain(network Network, apiKey string) *WhatsOnChain {
	return &WhatsOnChain{
		Network: network,
		ApiKey:  apiKey,
		baseURL: fmt.Sprintf("https://api.whatsonchain.com/v1/bsv/%s", network),
		client:  http.DefaultClient,
	}
}

// Assuming BlockHeader is defined elsewhere
func (w *WhatsOnChain) GetBlockHeader(height uint32) (header *BlockHeader, err error) {
	url := fmt.Sprintf("%s/block/%d/header", w.baseURL, height)
	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", w.ApiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

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

func (w *WhatsOnChain) IsValidRootForHeight(root *chainhash.Hash, height uint32) (bool, error) {
	if header, err := w.GetBlockHeader(height); err != nil {
		return false, err
	} else {
		return header.MerkleRoot.IsEqual(root), nil
	}
}

// Assuming BlockHeader is defined elsewhere
func (w *WhatsOnChain) CurrentHeight(ctx context.Context) (height uint32, err error) {
	url := fmt.Sprintf("%s/chain/info", w.baseURL)
	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	if err != nil {
		return
	}

	req.Header.Set("Authorization", w.ApiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return 0, fmt.Errorf("chain info not found for network %s", w.Network)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("failed to verify merkleroot for height %d: %v", height, resp.Status)
	}

	info := &ChainInfo{}
	if err := json.NewDecoder(resp.Body).Decode(info); err != nil {
		return 0, err
	}

	return info.Blocks, nil
}
