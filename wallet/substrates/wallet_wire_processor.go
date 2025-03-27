package substrates

import (
	"errors"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/serializer"
)

// WalletWireProcessor implements the WalletWire interface
type WalletWireProcessor struct {
	Wallet wallet.Interface
}

func NewWalletWireProcessor(wallet wallet.Interface) *WalletWireProcessor {
	return &WalletWireProcessor{Wallet: wallet}
}

func (w *WalletWireProcessor) TransmitToWallet(message []byte) ([]byte, error) {
	if len(message) == 0 {
		return nil, errors.New("empty message")
	}

	// First byte is call type
	callType := message[0]

	switch Call(callType) {
	case CallCreateAction:
		args, err := serializer.DeserializeCreateActionArgs(message[1:])
		if err != nil {
			return nil, err
		}
		return w.processCreateAction(*args)
	default:
		return nil, fmt.Errorf("unknown call type: %d", callType)
	}
}

func (w *WalletWireProcessor) processCreateAction(args wallet.CreateActionArgs) ([]byte, error) {
	result, err := w.Wallet.CreateAction(args)
	if err != nil {
		return nil, err
	}
	return serializer.SerializeCreateActionResult(result)
}
