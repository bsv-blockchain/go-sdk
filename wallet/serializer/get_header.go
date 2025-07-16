package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeGetHeaderArgs(args *wallet.GetHeaderArgs) ([]byte, error) {
	w := util.NewWriter()
	w.WriteVarInt(uint64(args.Height))
	return w.Buf, nil
}

func DeserializeGetHeaderArgs(data []byte) (*wallet.GetHeaderArgs, error) {

	r := util.NewReaderHoldError(data)

	args := &wallet.GetHeaderArgs{
		Height: r.ReadVarInt32(),
	}

	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error deserializing GetHeaderArgs: %w", r.Err)
	}
	return args, nil
}

func SerializeGetHeaderResult(result *wallet.GetHeaderResult) ([]byte, error) {
	return result.Header, nil
}

func DeserializeGetHeaderResult(data []byte) (*wallet.GetHeaderResult, error) {
	return &wallet.GetHeaderResult{
		Header: data,
	}, nil
}
