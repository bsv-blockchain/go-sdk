package spv

import (
	"context"

	"github.com/bsv-blockchain/go-sdk/chainhash"
)

type GullibleHeadersClient struct{}

func (g *GullibleHeadersClient) IsValidRootForHeight(merkleRoot *chainhash.Hash, height uint32) (bool, error) {
	// DO NOT USE IN A REAL PROJECT due to security risks of accepting any merkle root as valid without verification
	return true, nil
}

func (g *GullibleHeadersClient) CurrentHeight(ctx context.Context) (uint32, error) {
	return 800000, nil // Return a dummy height for testing
}
