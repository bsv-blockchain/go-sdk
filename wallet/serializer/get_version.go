package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeGetVersionResult(result *wallet.GetVersionResult) ([]byte, error) {
	w := util.NewWriter()

	// Error byte (0 for success)
	w.WriteByte(0)

	// Version string as UTF-8 bytes
	w.WriteString(result.Version)

	return w.Buf, nil
}

func DeserializeGetVersionResult(data []byte) (*wallet.GetVersionResult, error) {
	r := util.NewReader(data)

	// Read error byte
	_, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("error reading error byte: %w", err)
	}

	// Read version string
	version, err := r.ReadString()
	if err != nil {
		return nil, fmt.Errorf("error reading version string: %w", err)
	}

	return &wallet.GetVersionResult{
		Version: version,
	}, nil
}
