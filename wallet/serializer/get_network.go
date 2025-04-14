package serializer

import (
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeGetNetworkResult(result *wallet.GetNetworkResult) ([]byte, error) {
	w := newWriter()

	// Error byte (0 for success)
	w.writeByte(0)

	// Network byte (0 for mainnet, 1 for testnet)
	if result.Network == "mainnet" {
		w.writeByte(0)
	} else {
		w.writeByte(1)
	}

	return w.buf, nil
}

func DeserializeGetNetworkResult(data []byte) (*wallet.GetNetworkResult, error) {
	r := newReader(data)

	// Read error byte
	_, err := r.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading error byte: %w", err)
	}

	// Read network byte
	networkByte, err := r.readByte()
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
