package substrates

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/substrates/serializer"
)

// WalletWireTransceiver implements wallet.Interface
// A way to make remote calls to a wallet over a wallet wire.
type WalletWireTransceiver struct {
	Processor *WalletWireProcessor
}

func NewWalletWireTransceiver(processor *WalletWireProcessor) *WalletWireTransceiver {
	return &WalletWireTransceiver{Processor: processor}
}

func (t *WalletWireTransceiver) Transmit(call Call, originator string, params []byte) ([]byte, error) {
	// Create frame
	frame := serializer.WriteRequestFrame(byte(call), originator, params)

	// Transmit frame to processor
	result, err := t.Processor.TransmitToWallet(frame)
	if err != nil {
		return nil, err
	}

	// Parse response
	return serializer.ReadResultFrame(result)
}

func (t *WalletWireTransceiver) CreateAction(args wallet.CreateActionArgs) (*wallet.CreateActionResult, error) {
	// Serialize the request
	data, err := serializer.SerializeCreateActionArgs(&args)
	if err != nil {
		return nil, err
	}

	// Send to processor
	resp, err := t.Transmit(CallCreateAction, "", data)
	if err != nil {
		return nil, err
	}

	// Deserialize response
	return serializer.DeserializeCreateActionResult(resp)
}
