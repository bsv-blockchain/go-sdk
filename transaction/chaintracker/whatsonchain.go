package chaintracker

import (
	"context"
	"errors"
	"fmt"

	woc "github.com/mrz1836/go-whatsonchain"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/util"
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

// WhatsOnChain is a chain tracker backed by the WhatsOnChain API. It delegates
// its HTTP calls to github.com/mrz1836/go-whatsonchain, which centralizes URL
// building, API-key handling, and response parsing.
type WhatsOnChain struct {
	Network Network
	ApiKey  string

	httpClient util.HTTPClient
}

// ChainInfo mirrors the subset of WhatsOnChain chain info consumed by the SDK.
type ChainInfo struct {
	Blocks uint32 `json:"blocks"`
}

// WhatsOnChainOptions configures a WhatsOnChain constructed with NewWhatsOnChain.
type WhatsOnChainOptions struct {
	// HTTPClient is the util.HTTPClient used for every request (it satisfies
	// go-whatsonchain's HTTPInterface). When nil, the constructor defaults it to a
	// standard *http.Client.
	HTTPClient util.HTTPClient
}

// WithHTTPClient injects a custom util.HTTPClient, enabling timeouts, tracing,
// retries, and test doubles. The provided client cannot be nil.
func WithHTTPClient(client util.HTTPClient) func(*WhatsOnChainOptions) {
	if client == nil {
		panic("httpClient cannot be set to nil")
	}
	return func(opts *WhatsOnChainOptions) {
		opts.HTTPClient = client
	}
}

// NewWhatsOnChain constructs a WhatsOnChain chain tracker for the given network
// and API key. Additional behavior (such as a custom HTTP client) can be supplied
// through functional options.
func NewWhatsOnChain(network Network, apiKey string, opts ...func(*WhatsOnChainOptions)) *WhatsOnChain {
	options := &WhatsOnChainOptions{}
	for _, opt := range opts {
		opt(options)
	}

	return &WhatsOnChain{
		Network:    network,
		ApiKey:     apiKey,
		httpClient: options.HTTPClient,
	}
}

// client builds the underlying go-whatsonchain client, threading the caller's
// context. Construction performs no I/O, so building it per call is cheap and
// keeps context propagation intact.
func (w *WhatsOnChain) client(ctx context.Context) (woc.ClientInterface, error) {
	clientOpts := []woc.ClientOption{
		woc.WithNetwork(woc.NetworkType(w.Network)),
	}
	if w.ApiKey != "" {
		clientOpts = append(clientOpts, woc.WithAPIKey(w.ApiKey))
	}
	if w.httpClient != nil {
		clientOpts = append(clientOpts, woc.WithHTTPClient(w.httpClient))
	}
	return woc.NewClient(ctx, clientOpts...)
}

// GetBlockHeader returns the block header at the given height. It returns
// (nil, nil) when no block exists at that height, matching the previous behavior.
func (w *WhatsOnChain) GetBlockHeader(ctx context.Context, height uint32) (*BlockHeader, error) {
	client, err := w.client(ctx)
	if err != nil {
		return nil, err
	}

	info, err := client.GetBlockByHeight(ctx, int64(height))
	if err != nil {
		if errors.Is(err, woc.ErrBlockNotFound) {
			return nil, nil //nolint:nilnil // no block at this height is not an error
		}
		return nil, fmt.Errorf("failed to get block header for height %d: %w", height, err)
	}

	return blockInfoToHeader(info)
}

func (w *WhatsOnChain) IsValidRootForHeight(ctx context.Context, root *chainhash.Hash, height uint32) (bool, error) {
	if header, err := w.GetBlockHeader(ctx, height); err != nil {
		return false, err
	} else {
		return header.MerkleRoot.IsEqual(root), nil
	}
}

// CurrentHeight returns the height of the longest chain.
func (w *WhatsOnChain) CurrentHeight(ctx context.Context) (height uint32, err error) {
	client, err := w.client(ctx)
	if err != nil {
		return 0, err
	}

	info, err := client.GetChainInfo(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get chain info for network %s: %w", w.Network, err)
	}

	return uint32(info.Blocks), nil //nolint:gosec // G115 -- block height fits in uint32
}

// blockInfoToHeader converts a go-whatsonchain BlockInfo into the SDK BlockHeader.
func blockInfoToHeader(info *woc.BlockInfo) (*BlockHeader, error) {
	hash, err := hashFromHex(info.Hash)
	if err != nil {
		return nil, fmt.Errorf("invalid block hash: %w", err)
	}
	merkleRoot, err := hashFromHex(info.MerkleRoot)
	if err != nil {
		return nil, fmt.Errorf("invalid merkle root: %w", err)
	}
	prevHash, err := hashFromHex(info.PreviousBlockHash)
	if err != nil {
		return nil, fmt.Errorf("invalid previous block hash: %w", err)
	}

	return &BlockHeader{
		Hash:       hash,
		Height:     uint32(info.Height),  //nolint:gosec // G115 -- block height fits in uint32
		Version:    uint32(info.Version), //nolint:gosec // G115 -- block version fits in uint32
		MerkleRoot: merkleRoot,
		Time:       uint32(info.Time),  //nolint:gosec // G115 -- block time fits in uint32
		Nonce:      uint32(info.Nonce), //nolint:gosec // G115 -- nonce fits in uint32
		Bits:       info.Bits,
		PrevHash:   prevHash,
	}, nil
}

// hashFromHex parses a hex-encoded hash, returning nil for an empty string.
func hashFromHex(s string) (*chainhash.Hash, error) {
	if s == "" {
		return nil, nil //nolint:nilnil // an absent hash (e.g. genesis prev-hash) is not an error
	}
	return chainhash.NewHashFromHex(s)
}
