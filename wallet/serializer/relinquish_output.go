package serializer

import (
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeRelinquishOutputArgs(args *wallet.RelinquishOutputArgs) ([]byte, error) {
	w := newWriter()

	// Write basket string with length prefix
	w.writeString(args.Basket)

	// Write outpoint string with length prefix
	outpoint, err := encodeOutpoint(args.Output)
	if err != nil {
		return nil, fmt.Errorf("error relinquish output encode output: %v", err)
	}
	w.writeBytes(outpoint)

	return w.buf, nil
}

func DeserializeRelinquishOutputArgs(data []byte) (*wallet.RelinquishOutputArgs, error) {
	r := newReaderHoldError(data)
	args := &wallet.RelinquishOutputArgs{
		Basket: r.readString(),
	}
	outpoint, err := decodeOutpoint(r.readBytes(OutpointSize))
	if r.err != nil {
		return nil, fmt.Errorf("error reading relinquish output: %w", r.err)
	} else if err != nil {
		return nil, fmt.Errorf("error decoding relinqush outpoint: %w", r.err)
	}
	args.Output = outpoint
	return args, nil
}

func SerializeRelinquishOutputResult(result *wallet.RelinquishOutputResult) ([]byte, error) {
	w := newWriter()

	// Write 1 byte boolean flag (1 = true, 0 = false)
	if result.Relinquished {
		w.writeByte(1)
	} else {
		w.writeByte(0)
	}

	return w.buf, nil
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
