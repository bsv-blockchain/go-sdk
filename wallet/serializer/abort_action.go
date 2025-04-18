package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeAbortActionArgs(args *wallet.AbortActionArgs) ([]byte, error) {
	w := util.NewWriter()

	// Serialize reference
	w.WriteBytes(args.Reference)

	return w.Buf, nil
}

func DeserializeAbortActionArgs(data []byte) (*wallet.AbortActionArgs, error) {
	r := util.NewReaderHoldError(data)
	args := &wallet.AbortActionArgs{}

	// Read reference
	args.Reference = r.ReadRemaining()

	if r.Err != nil {
		return nil, fmt.Errorf("error reading abort action args: %w", r.Err)
	}

	return args, nil
}

func SerializeAbortActionResult(result *wallet.AbortActionResult) ([]byte, error) {
	w := util.NewWriter()
	w.WriteByte(0) // errorByte = 0 (success)
	return w.Buf, nil
}

func DeserializeAbortActionResult(data []byte) (*wallet.AbortActionResult, error) {
	r := util.NewReaderHoldError(data)

	// Read error byte
	errorByte := r.ReadByte()
	if errorByte != 0 {
		// Read error message if present
		msgLen := r.ReadVarInt()
		msg := r.ReadBytes(int(msgLen))
		return nil, fmt.Errorf("abort action failed: %s", string(msg))
	}

	return &wallet.AbortActionResult{
		Aborted: true,
	}, nil
}
