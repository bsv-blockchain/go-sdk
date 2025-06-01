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

type Protocol string

const (
	ProtocolSHIP Protocol = "SHIP"
	ProtocolSLAP Protocol = "SLAP"
)

type TaggedBEEF struct {
	Beef   []byte
	Topics []string
}

type AppliedTransaction struct {
	Txid  *chainhash.Hash
	Topic string
}

type TopicData struct {
	Data any
	Deps []*Outpoint
}

type AdmittanceInstructions struct {
	OutputsToAdmit []uint32
	CoinsToRetain  []uint32
	CoinsRemoved   []uint32
	AncillaryTxids []*chainhash.Hash
}
type Steak map[string]*AdmittanceInstructions

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

type MetaData struct {
	Name        string `json:"name"`
	Description string `json:"shortDescription"`
	Icon        string `json:"iconURL"`
	Version     string `json:"version"`
	InfoUrl     string `json:"informationURL"`
}
