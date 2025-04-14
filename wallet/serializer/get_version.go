package serializer

import (
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeGetVersionResult(result *wallet.GetVersionResult) ([]byte, error) {
	w := newWriter()

	// Error byte (0 for success)
	w.writeByte(0)

	// Version string as UTF-8 bytes
	w.writeString(result.Version)

	return w.buf, nil
}

func DeserializeGetVersionResult(data []byte) (*wallet.GetVersionResult, error) {
	r := newReader(data)

	// Read error byte
	_, err := r.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading error byte: %w", err)
	}

	// Read version string
	version, err := r.readString()
	if err != nil {
		return nil, fmt.Errorf("error reading version string: %w", err)
	}

	return &wallet.GetVersionResult{
		Version: version,
	}, nil
}
