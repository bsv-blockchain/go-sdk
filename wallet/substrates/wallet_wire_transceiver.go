package substrates

import (
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
	// Serialize the request
	data, err := SerializeCreateActionArgs(&args)
	if err != nil {
		return nil, err
	}

	// Send to processor
	resp, err := t.Processor.TransmitToWallet(data)
	if err != nil {
		return nil, err
	}

	// Deserialize response
	return DeserializeCreateActionResult(resp)
}
