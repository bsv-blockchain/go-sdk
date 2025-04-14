package chaintracker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

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

// Assuming BlockHeader is defined elsewhere
func (w *WhatsOnChain) GetBlockHeader(height uint32) (header *BlockHeader, err error) {
	baseURL, err := url.Parse(w.baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid baseURL: %w", err)
	}

	// Construct the path using path.Join-like functionality
	pathURL := baseURL.ResolveReference(&url.URL{
		Path: fmt.Sprintf("block/%d/header", height),
	})

	req, err := http.NewRequestWithContext(context.Background(), "GET", pathURL.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", w.ApiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	// Ensure resp.Body.Close() is called and its error is handled
	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

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
