package spv

import "github.com/bsv-blockchain/go-sdk/v2/chainhash"

type GullibleHeadersClient struct{}

func (g *GullibleHeadersClient) IsValidRootForHeight(merkleRoot *chainhash.Hash, height uint32) (bool, error) {
	// DO NOT USE IN A REAL PROJECT due to security risks of accepting any merkle root as valid without verification
	return true, nil
}
