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
	w := util.NewWriter()
	w.WriteByte(0) // errorByte = 0
	w.WriteBytes(result.Header)
	return w.Buf, nil
}

func DeserializeGetHeaderResult(data []byte) (*wallet.GetHeaderResult, error) {
	r := util.NewReaderHoldError(data)

	// Read error byte (must be 0 for success)
	if errByte := r.ReadByte(); errByte != 0 {
		return nil, fmt.Errorf("error byte indicates failure: %d", errByte)
	}

	// Read remaining bytes as header
	headerBytes := r.ReadRemaining()
	if r.Err != nil {
		return nil, fmt.Errorf("error reading header bytes: %w", r.Err)
	}

	return &wallet.GetHeaderResult{
		Header: headerBytes,
	}, nil
}
