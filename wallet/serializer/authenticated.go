package serializer

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func SerializeIsAuthenticatedResult(result *wallet.AuthenticatedResult) ([]byte, error) {
	w := util.NewWriter()

	// Authenticated flag (1=true, 0=false)
	if result.Authenticated {
		w.WriteByte(1)
	} else {
		w.WriteByte(0)
	}

	return w.Buf, nil
}

func DeserializeIsAuthenticatedResult(data []byte) (*wallet.AuthenticatedResult, error) {
	if len(data) != 1 {
		return nil, fmt.Errorf("invalid data length for authenticated result")
	}

	// Second byte is authenticated flag
	result := &wallet.AuthenticatedResult{
		Authenticated: data[0] == 1,
	}

	return result, nil
}

func SerializeWaitAuthenticatedResult(_ *wallet.AuthenticatedResult) ([]byte, error) {
	return nil, nil
}

func DeserializeWaitAuthenticatedResult(_ []byte) (*wallet.AuthenticatedResult, error) {
	return &wallet.AuthenticatedResult{
		Authenticated: true,
	}, nil
}
