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
	TxidsToInclude []*chainhash.Hash
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
	Name        string
	Description string
	Icon        string
	Version     string
	InfoUrl     string
}
