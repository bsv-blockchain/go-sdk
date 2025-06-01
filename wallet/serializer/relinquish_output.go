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
	outpoint, err := decodeOutpoint(r.ReadBytes(outpointSize))
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
	w := util.NewWriter()

	// Write 1 byte boolean flag (1 = true, 0 = false)
	if result.Relinquished {
		w.WriteByte(1)
	} else {
		w.WriteByte(0)
	}

	return w.Buf, nil
}

func DeserializeRelinquishOutputResult(data []byte) (*wallet.RelinquishOutputResult, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("invalid result data length")
	}

	result := &wallet.RelinquishOutputResult{
		Relinquished: data[0] == 1,
	}
	return result, nil
}
