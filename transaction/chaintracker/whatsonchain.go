package chaintracker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

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

type headerCache map[uint32]*BlockHeader

func (m headerCache) Insert(header *BlockHeader) {
	if header == nil {
		return
	}
	const maxHeaderCacheSize = 100
	if len(m) >= maxHeaderCacheSize {
		// remove an arbitrary element, range over map is randomly ordered
		for k := range m {
			delete(m, k)
			break
		}
	}
	m[header.Height] = header
}

func (m headerCache) Get(height uint32) *BlockHeader {
	return m[height]
}

type WhatsOnChain struct {
	Network Network
	ApiKey  string
	baseURL string
	client  *http.Client
	mutex   *sync.Mutex // Serialize to avoid 429 errors and prevent duplicate requests
	cache   headerCache // Cache recent to de-duplicate requests
}

type ChainInfo struct {
	Blocks uint32 `json:"blocks"`
}

func NewWhatsOnChain(network Network, apiKey string) *WhatsOnChain {
	return &WhatsOnChain{
		Network: network,
		ApiKey:  apiKey,
		baseURL: fmt.Sprintf("https://api.whatsonchain.com/v1/bsv/%s", network),
		client: &http.Client{
			// Empty transport to not use HTTP/2, which seems to mere easily trigger 429 errors
			Transport: &http.Transport{},
		},
		mutex: &sync.Mutex{},
		cache: make(headerCache),
	}
}

// Assuming BlockHeader is defined elsewhere
func (w *WhatsOnChain) GetBlockHeader(ctx context.Context, height uint32) (header *BlockHeader, err error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	if cacheHeader := w.cache.Get(height); cacheHeader != nil {
		return cacheHeader, nil
	}
	url := fmt.Sprintf("%s/block/%d/header", w.baseURL, height)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	w.setHTTPHeaders(req)

	resp, err := w.client.Do(req)
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
	w.cache.Insert(header)

	return header, nil
}

func (w *WhatsOnChain) IsValidRootForHeight(ctx context.Context, root *chainhash.Hash, height uint32) (bool, error) {
	if header, err := w.GetBlockHeader(ctx, height); err != nil {
		return false, err
	} else {
		return header.MerkleRoot.IsEqual(root), nil
	}
}

// Assuming BlockHeader is defined elsewhere
func (w *WhatsOnChain) CurrentHeight(ctx context.Context) (height uint32, err error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	url := fmt.Sprintf("%s/chain/info", w.baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}
	w.setHTTPHeaders(req)

	resp, err := w.client.Do(req)
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

func (w *WhatsOnChain) setHTTPHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/json")
	if w.ApiKey != "" {
		req.Header.Set("Authorization", w.ApiKey)
	}
}
