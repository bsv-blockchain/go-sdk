package substrates

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/serializer"
)

// WalletWireTransceiver implements wallet.Interface
// A way to make remote calls to a wallet over a wallet wire.
type WalletWireTransceiver struct {
	Wire WalletWire
}

func NewWalletWireTransceiver(processor *WalletWireProcessor) *WalletWireTransceiver {
	return &WalletWireTransceiver{Wire: processor}
}

func (t *WalletWireTransceiver) Transmit(call Call, originator string, params []byte) ([]byte, error) {
	// Create frame
	frame := serializer.WriteRequestFrame(serializer.RequestFrame{
		Call:       byte(call),
		Originator: originator,
		Params:     params,
	})

	// Transmit frame to processor
	result, err := t.Wire.TransmitToWallet(frame)
	if err != nil {
		return nil, err
	}

	// Parse response
	return serializer.ReadResultFrame(result)
}

func (t *WalletWireTransceiver) CreateAction(args wallet.CreateActionArgs, originator string) (*wallet.CreateActionResult, error) {
	// Serialize the request
	data, err := serializer.SerializeCreateActionArgs(&args)
	if err != nil {
		return nil, err
	}

	// Send to processor
	resp, err := t.Transmit(CallCreateAction, originator, data)
	if err != nil {
		return nil, err
	}

	// Deserialize response
	return serializer.DeserializeCreateActionResult(resp)
}
