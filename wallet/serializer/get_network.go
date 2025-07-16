package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const (
	networkMainnetCode = 0
	networkTestnetCode = 1
)

func SerializeGetNetworkResult(result *wallet.GetNetworkResult) ([]byte, error) {
	w := util.NewWriter()

	// Network byte (0 for mainnet, 1 for testnet)
	if result.Network == wallet.NetworkMainnet {
		w.WriteByte(networkMainnetCode)
	} else {
		w.WriteByte(networkTestnetCode)
	}

	return w.Buf, nil
}

func DeserializeGetNetworkResult(data []byte) (*wallet.GetNetworkResult, error) {
	r := util.NewReaderHoldError(data)

	// Read network byte
	result := new(wallet.GetNetworkResult)
	switch r.ReadByte() {
	case networkMainnetCode:
		result.Network = wallet.NetworkMainnet
	case networkTestnetCode:
		result.Network = wallet.NetworkTestnet
	}

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error reading get network result: %w", r.Err)
	}

	return result, nil
}
