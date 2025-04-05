package serializer

import (
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeGetHeightResult(result *wallet.GetHeightResult) ([]byte, error) {
	w := newWriter()
	w.writeVarInt(uint64(result.Height))
	return w.buf, nil
}

func DeserializeGetHeightResult(data []byte) (*wallet.GetHeightResult, error) {
	r := newReaderHoldError(data)
	height := r.readVarInt32()
	if r.err != nil {
		return nil, fmt.Errorf("error reading height: %w", r.err)
	}
	return &wallet.GetHeightResult{
		Height: height,
	}, nil
}
