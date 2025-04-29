package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeAuthenticatedResult(result *wallet.AuthenticatedResult) ([]byte, error) {
	w := util.NewWriter()

	// Error byte (0 for success)
	w.WriteByte(0)

	// Authenticated flag (1=true, 0=false)
	if result.Authenticated {
		w.WriteByte(1)
	} else {
		w.WriteByte(0)
	}

	return w.Buf, nil
}

func DeserializeAuthenticatedResult(data []byte) (*wallet.AuthenticatedResult, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("invalid data length for authenticated result")
	}

	// First byte is error code (0=success)
	if data[0] != 0 {
		return nil, fmt.Errorf("error byte indicates failure")
	}

	// Second byte is authenticated flag
	result := &wallet.AuthenticatedResult{
		Authenticated: data[1] == 1,
	}

	return result, nil
}
