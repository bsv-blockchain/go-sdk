package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/v2/util"
	"github.com/bsv-blockchain/go-sdk/v2/wallet"
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

func SerializeAbortActionResult(*wallet.AbortActionResult) ([]byte, error) {
	// Frame indicates error or not, no additional data
	return nil, nil
}

func DeserializeAbortActionResult([]byte) (*wallet.AbortActionResult, error) {
	// Accepted is implicit
	return &wallet.AbortActionResult{
		Aborted: true,
	}, nil
}
