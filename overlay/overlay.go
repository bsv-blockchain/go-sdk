// Package overlay implements the SHIP (Simplified Hosted Infrastructure Protocol) and SLAP
// (Simplified Lookup And Payment) protocols for topic-based message broadcasting and discovery.
// It provides network-aware configurations for Mainnet, Testnet, and local development, supports
// tagged BEEF and STEAK transaction handling, and includes admin token management for service
// operations. The overlay system enables efficient routing and discovery of services across
// the BSV blockchain network.
package overlay

import (
	"github.com/bsv-blockchain/go-sdk/chainhash"
)

// Protocol represents the overlay protocol type (SHIP or SLAP)
type Protocol string

const (
	ProtocolSHIP Protocol = "SHIP"
	ProtocolSLAP Protocol = "SLAP"
)

// TaggedBEEF represents a BEEF (Background Evaluation Extended Format) transaction with associated overlay topics
type TaggedBEEF struct {
	Beef   []byte
	Topics []string
}

// AppliedTransaction represents a transaction that has been applied to a specific overlay topic
type AppliedTransaction struct {
	Txid  *chainhash.Hash
	Topic string
}

// TopicData represents data associated with an overlay topic including dependencies
type TopicData struct {
	Data any
	Deps []*Outpoint
}

// AdmittanceInstructions specify which outputs to admit and which coins to retain when submitting to overlay topics
type AdmittanceInstructions struct {
	OutputsToAdmit []uint32
	CoinsToRetain  []uint32
	CoinsRemoved   []uint32
	AncillaryTxids []*chainhash.Hash
}

// Steak represents a Submitted Transaction Execution AcKnowledgment mapping topics to their admittance instructions
type Steak map[string]*AdmittanceInstructions

// Network represents the BSV network type
type Network int

var (
	NetworkMainnet Network = 0
	NetworkTestnet Network = 1
	NetworkLocal   Network = 2
)

var NetworkNames = map[Network]string{
	NetworkMainnet: "mainnet",
	NetworkTestnet: "testnet",
	NetworkLocal:   "local",
}

// MetaData contains overlay service metadata information
type MetaData struct {
	Name        string `json:"name"`
	Description string `json:"shortDescription"`
	Icon        string `json:"iconURL"`
	Version     string `json:"version"`
	InfoUrl     string `json:"informationURL"`
}
