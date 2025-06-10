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
	r := util.NewReaderHoldError(data)

	// Read error byte
	if r.ReadByte() != 0 {
		return nil, fmt.Errorf("error byte indicates failure")
	}

	// Read version string
	result := &wallet.GetVersionResult{
		Version: r.ReadString(),
	}

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error reading get version result: %w", r.Err)
	}

	return result, nil
}
