package overlay

import (
	"github.com/bitcoin-sv/go-sdk/chainhash"
	"github.com/bitcoin-sv/go-sdk/transaction"
)

type Protocol string

const (
	ProtocolSHIP Protocol = "SHIP"
	ProtocolSLAP Protocol = "SLAP"
)

type Output struct {
	Outpoint        *Outpoint
	Script          []byte
	Satoshis        uint64
	Topic           string
	Spent           *chainhash.Hash
	OutputsConsumed []*Outpoint
	ConsumedBy      []*Outpoint
	Beef            []byte
	BlockHeight     uint32
	BlockIdx        uint64
}

type AppliedTransaction struct {
	Txid  *chainhash.Hash
	Topic string
}

type Steak map[string]*Admittance

type SubmitContext struct {
	Txid            *chainhash.Hash
	Tx              *transaction.Transaction
	Beef            []byte
	TopicAdmittance Steak
	TopicInputs     map[string][]*Output
}

type TopicData struct {
	Data any
	Deps []*Outpoint
}

type Admittance struct {
	OutputsToAdmit []uint32
	CoinsToRetain  []uint32
	CoinsRemoved   []uint32
	InputData      map[uint32]any
	OutputData     map[uint32]any
}

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
