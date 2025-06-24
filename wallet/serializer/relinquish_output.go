package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeRelinquishOutputArgs(args *wallet.RelinquishOutputArgs) ([]byte, error) {
	w := util.NewWriter()

	// Write basket string with length prefix
	w.WriteString(args.Basket)

	// Write outpoint string with length prefix
	w.WriteBytes(encodeOutpoint(&args.Output))

	return w.Buf, nil
}

func DeserializeRelinquishOutputArgs(data []byte) (*wallet.RelinquishOutputArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.RelinquishOutputArgs{
		Basket: r.ReadString(),
	}
	outpoint, err := decodeOutpoint(&r.Reader)
	r.CheckComplete()
	if r.Err != nil {
		return nil, fmt.Errorf("error reading relinquish output: %w", r.Err)
	} else if err != nil {
		return nil, fmt.Errorf("error decoding relinqush outpoint: %w", r.Err)
	}
	args.Output = *outpoint
	return args, nil
}

func SerializeRelinquishOutputResult(result *wallet.RelinquishOutputResult) ([]byte, error) {
	return nil, nil
}

func DeserializeRelinquishOutputResult(data []byte) (*wallet.RelinquishOutputResult, error) {
	if len(data) > 0 {
		return nil, fmt.Errorf("invalid result data length, expected 0, got %d", len(data))
	}
	// Error in frame, empty data means success
	return &wallet.RelinquishOutputResult{
		Relinquished: true,
	}, nil
}
