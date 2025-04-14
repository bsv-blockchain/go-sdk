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
	r := util.NewReader(data)

	// Read error byte
	_, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("error reading error byte: %w", err)
	}

	// Read network byte
	networkByte, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("error reading network byte: %w", err)
	}

	result := &wallet.GetNetworkResult{
		Network: "mainnet",
	}
	if networkByte != 0 {
		result.Network = "testnet"
	}

	return result, nil
}
