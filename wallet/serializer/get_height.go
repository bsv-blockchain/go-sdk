package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeGetHeightResult(result *wallet.GetHeightResult) ([]byte, error) {
	w := util.NewWriter()
	w.WriteVarInt(uint64(result.Height))
	return w.Buf, nil
}

func DeserializeGetHeightResult(data []byte) (*wallet.GetHeightResult, error) {
	r := util.NewReaderHoldError(data)
	height := r.ReadVarInt32()
	if r.Err != nil {
		return nil, fmt.Errorf("error reading height: %w", r.Err)
	}
	return &wallet.GetHeightResult{
		Height: height,
	}, nil
}
