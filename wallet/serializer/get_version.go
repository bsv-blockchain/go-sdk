package serializer

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeGetVersionResult(result *wallet.GetVersionResult) ([]byte, error) {
	return []byte(result.Version), nil
}

func DeserializeGetVersionResult(data []byte) (*wallet.GetVersionResult, error) {
	return &wallet.GetVersionResult{
		Version: string(data),
	}, nil
}
