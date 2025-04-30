package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeGetNetworkResult(result *wallet.GetNetworkResult) ([]byte, error) {
	w := util.NewWriter()

	// Error byte (0 for success)
	w.WriteByte(0)

	// Network byte (0 for mainnet, 1 for testnet)
	if result.Network == "mainnet" {
		w.WriteByte(0)
	} else {
		w.WriteByte(1)
	}

	return w.Buf, nil
}

func DeserializeGetNetworkResult(data []byte) (*wallet.GetNetworkResult, error) {
	r := util.NewReaderHoldError(data)

	// Read error byte
	if r.ReadByte() != 0 {
		return nil, fmt.Errorf("error byte indicates failure")
	}

	// Read network byte
	result := &wallet.GetNetworkResult{
		Network: "mainnet",
	}
	if r.ReadByte() != 0 {
		result.Network = "testnet"
	}

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error reading get network result: %w", r.Err)
	}

	return result, nil
}
