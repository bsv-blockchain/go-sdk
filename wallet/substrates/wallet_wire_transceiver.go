package substrates

import (
	"errors"
	"github.com/bsv-blockchain/go-sdk/wallet"
)
// WalletWireTransceiver implements wallet.Interface
// A way to make remote calls to a wallet over a wallet wire.
type WalletWireTransceiver struct {
	Processor *WalletWireProcessor
}

func NewWalletWireTransceiver(processor *WalletWireProcessor) *WalletWireTransceiver {
	return &WalletWireTransceiver{Processor: processor}
}

func (t *WalletWireTransceiver) CreateAction(args wallet.CreateActionArgs) (*wallet.CreateActionResult, error) {
	// TODO: Implement create action
	return nil, errors.New("not implemented")
}
