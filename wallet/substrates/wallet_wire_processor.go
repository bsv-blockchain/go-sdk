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

	requestFrame, err := serializer.ReadRequestFrame(message)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize request frame: %w", err)
	}
	var response []byte
	switch Call(requestFrame.Call) {
	case CallCreateAction:
		args, err := serializer.DeserializeCreateActionArgs(requestFrame.Params)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize create action args: %w", err)
		}
		response, err = w.processCreateAction(*args, requestFrame.Originator)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown call type: %d", requestFrame.Call)
	}
	return serializer.WriteResultFrame(response, nil), nil
}

func (w *WalletWireProcessor) processCreateAction(args wallet.CreateActionArgs, originator string) ([]byte, error) {
	result, err := w.Wallet.CreateAction(args, originator)
	if err != nil {
		return nil, err
	}
	return serializer.SerializeCreateActionResult(result)
}
