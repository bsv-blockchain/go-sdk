package substrates

import (
	"fmt"
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

func (t *WalletWireTransceiver) transmit(call Call, originator string, params []byte) ([]byte, error) {
	// Create frame
	frame := serializer.WriteRequestFrame(serializer.RequestFrame{
		Call:       byte(call),
		Originator: originator,
		Params:     params,
	})

	// Transmit frame to processor
	result, err := t.Wire.TransmitToWallet(frame)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit call to wallet wire: %w", err)
	}

	// Parse response
	return serializer.ReadResultFrame(result)
}

func (t *WalletWireTransceiver) CreateAction(args wallet.CreateActionArgs, originator string) (*wallet.CreateActionResult, error) {
	// Serialize the request
	data, err := serializer.SerializeCreateActionArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize create action arguments: %w", err)
	}

	// Send to processor
	resp, err := t.transmit(CallCreateAction, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit create action call: %w", err)
	}

	// Deserialize response
	return serializer.DeserializeCreateActionResult(resp)
}

func (t *WalletWireTransceiver) SignAction(args wallet.SignActionArgs, originator string) (*wallet.SignActionResult, error) {
	// Serialize the request
	data, err := serializer.SerializeSignActionArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize sign action arguments: %w", err)
	}

	// Send to processor
	resp, err := t.transmit(CallSignAction, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit sign action call: %w", err)
	}

	// Deserialize response
	return serializer.DeserializeSignActionResult(resp)
}

func (t *WalletWireTransceiver) AbortAction(args wallet.AbortActionArgs, originator string) (*wallet.AbortActionResult, error) {
	// Serialize the request
	data, err := serializer.SerializeAbortActionArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize abort action arguments: %w", err)
	}

	// Send to processor
	resp, err := t.transmit(CallAbortAction, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit abort action call: %w", err)
	}

	// Deserialize response
	return serializer.DeserializeAbortActionResult(resp)
}

func (t *WalletWireTransceiver) ListActions(args wallet.ListActionsArgs, originator string) (*wallet.ListActionsResult, error) {
	// Serialize the request
	data, err := serializer.SerializeListActionsArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize list action arguments: %w", err)
	}

	// Send to processor
	resp, err := t.transmit(CallListActions, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit list action call: %w", err)
	}

	// Deserialize response
	return serializer.DeserializeListActionsResult(resp)
}

func (t *WalletWireTransceiver) InternalizeAction(args wallet.InternalizeActionArgs, originator string) (*wallet.InternalizeActionResult, error) {
	// Serialize the request
	data, err := serializer.SerializeInternalizeActionArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize internalize action arguments: %w", err)
	}

	// Send to processor
	resp, err := t.transmit(CallInternalizeAction, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit internalize action call: %w", err)
	}

	// Deserialize response
	return serializer.DeserializeInternalizeActionResult(resp)
}

func (t *WalletWireTransceiver) ListOutputs(args wallet.ListOutputsArgs, originator string) (*wallet.ListOutputsResult, error) {
	// Serialize the request
	data, err := serializer.SerializeListOutputsArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize list outputs arguments: %w", err)
	}

	// Send to processor
	resp, err := t.transmit(CallListOutputs, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit list outputs call: %w", err)
	}

	// Deserialize response
	return serializer.DeserializeListOutputsResult(resp)
}

func (t *WalletWireTransceiver) RelinquishOutput(args wallet.RelinquishOutputArgs, originator string) (*wallet.RelinquishOutputResult, error) {
	data, err := serializer.SerializeRelinquishOutputArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize relinquish output arguments: %w", err)
	}
	resp, err := t.transmit(CallRelinquishOutput, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit relinquish output call: %w", err)
	}
	return serializer.DeserializeRelinquishOutputResult(resp)
}

func (t *WalletWireTransceiver) GetPublicKey(args wallet.GetPublicKeyArgs, originator string) (*wallet.GetPublicKeyResult, error) {
	data, err := serializer.SerializeGetPublicKeyArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize get public key arguments: %w", err)
	}
	resp, err := t.transmit(CallGetPublicKey, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit get public key call: %w", err)
	}
	return serializer.DeserializeGetPublicKeyResult(resp)
}

func (t *WalletWireTransceiver) RevealCounterpartyKeyLinkage(args wallet.RevealCounterpartyKeyLinkageArgs, originator string) (*wallet.RevealCounterpartyKeyLinkageResult, error) {
	data, err := serializer.SerializeRevealCounterpartyKeyLinkageArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize reveal counterparty key linkage arguments: %w", err)
	}
	resp, err := t.transmit(CallRevealCounterpartyKeyLinkage, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit reveal counterparty key linkage call: %w", err)
	}
	return serializer.DeserializeRevealCounterpartyKeyLinkageResult(resp)
}

func (t *WalletWireTransceiver) RevealSpecificKeyLinkage(args wallet.RevealSpecificKeyLinkageArgs, originator string) (*wallet.RevealSpecificKeyLinkageResult, error) {
	data, err := serializer.SerializeRevealSpecificKeyLinkageArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize reveal specific key linkage arguments: %w", err)
	}
	resp, err := t.transmit(CallRevealSpecificKeyLinkage, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit reveal specific key linkage call: %w", err)
	}
	return serializer.DeserializeRevealSpecificKeyLinkageResult(resp)
}

func (t *WalletWireTransceiver) Encrypt(args wallet.EncryptArgs, originator string) (*wallet.EncryptResult, error) {
	data, err := serializer.SerializeEncryptArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize encrypt arguments: %w", err)
	}
	resp, err := t.transmit(CallEncrypt, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit encrypt call: %w", err)
	}
	return serializer.DeserializeEncryptResult(resp)
}

func (t *WalletWireTransceiver) Decrypt(args wallet.DecryptArgs, originator string) (*wallet.DecryptResult, error) {
	data, err := serializer.SerializeDecryptArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize decrypt arguments: %w", err)
	}
	resp, err := t.transmit(CallDecrypt, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit decrypt call: %w", err)
	}
	return serializer.DeserializeDecryptResult(resp)
}

func (t *WalletWireTransceiver) CreateHmac(args wallet.CreateHmacArgs, originator string) (*wallet.CreateHmacResult, error) {
	data, err := serializer.SerializeCreateHmacArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize create hmac arguments: %w", err)
	}
	resp, err := t.transmit(CallCreateHmac, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit create hmac call: %w", err)
	}
	return serializer.DeserializeCreateHmacResult(resp)
}

func (t *WalletWireTransceiver) VerifyHmac(args wallet.VerifyHmacArgs, originator string) (*wallet.VerifyHmacResult, error) {
	data, err := serializer.SerializeVerifyHmacArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize verify hmac arguments: %w", err)
	}
	resp, err := t.transmit(CallVerifyHmac, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit verify hmac call: %w", err)
	}
	return serializer.DeserializeVerifyHmacResult(resp)
}

func (t *WalletWireTransceiver) CreateSignature(args wallet.CreateSignatureArgs, originator string) (*wallet.CreateSignatureResult, error) {
	data, err := serializer.SerializeCreateSignatureArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize create signature arguments: %w", err)
	}
	resp, err := t.transmit(CallCreateSignature, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit create signature call: %w", err)
	}
	return serializer.DeserializeCreateSignatureResult(resp)
}

func (t *WalletWireTransceiver) VerifySignature(args wallet.VerifySignatureArgs, originator string) (*wallet.VerifySignatureResult, error) {
	data, err := serializer.SerializeVerifySignatureArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize verify signature arguments: %w", err)
	}
	resp, err := t.transmit(CallVerifySignature, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit verify signature call: %w", err)
	}
	return serializer.DeserializeVerifySignatureResult(resp)
}

func (t *WalletWireTransceiver) AcquireCertificate(args wallet.AcquireCertificateArgs, originator string) (*wallet.Certificate, error) {
	data, err := serializer.SerializeAcquireCertificateArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize acquire certificate arguments: %w", err)
	}
	resp, err := t.transmit(CallAcquireCertificate, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit acquire certificate call: %w", err)
	}
	return serializer.DeserializeCertificate(resp)
}

func (t *WalletWireTransceiver) ListCertificates(args wallet.ListCertificatesArgs, originator string) (*wallet.ListCertificatesResult, error) {
	data, err := serializer.SerializeListCertificatesArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize list certificates arguments: %w", err)
	}
	resp, err := t.transmit(CallListCertificates, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit list certificates call: %w", err)
	}
	return serializer.DeserializeListCertificatesResult(resp)
}

func (t *WalletWireTransceiver) ProveCertificate(args wallet.ProveCertificateArgs, originator string) (*wallet.ProveCertificateResult, error) {
	data, err := serializer.SerializeProveCertificateArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize prove certificate arguments: %w", err)
	}
	resp, err := t.transmit(CallProveCertificate, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit prove certificate call: %w", err)
	}
	return serializer.DeserializeProveCertificateResult(resp)
}

func (t *WalletWireTransceiver) RelinquishCertificate(args wallet.RelinquishCertificateArgs, originator string) (*wallet.RelinquishCertificateResult, error) {
	data, err := serializer.SerializeRelinquishCertificateArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize relinquish certificate arguments: %w", err)
	}
	resp, err := t.transmit(CallRelinquishCertificate, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit relinquish certificate call: %w", err)
	}
	return serializer.DeserializeRelinquishCertificateResult(resp)
}

func (t *WalletWireTransceiver) DiscoverByIdentityKey(args wallet.DiscoverByIdentityKeyArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	data, err := serializer.SerializeDiscoverByIdentityKeyArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize discover by identity key arguments: %w", err)
	}
	resp, err := t.transmit(CallDiscoverByIdentityKey, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit discover by identity key call: %w", err)
	}
	return serializer.DeserializeDiscoverCertificatesResult(resp)
}

func (t *WalletWireTransceiver) DiscoverByAttributes(args wallet.DiscoverByAttributesArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	data, err := serializer.SerializeDiscoverByAttributesArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize discover by attributes arguments: %w", err)
	}
	resp, err := t.transmit(CallDiscoverByAttributes, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit discover by attributes call: %w", err)
	}
	return serializer.DeserializeDiscoverCertificatesResult(resp)
}

func (t *WalletWireTransceiver) IsAuthenticated(args interface{}, originator string) (*wallet.AuthenticatedResult, error) {
	resp, err := t.transmit(CallIsAuthenticated, originator, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit is authenticated call: %w", err)
	}
	return serializer.DeserializeAuthenticatedResult(resp)
}

func (t *WalletWireTransceiver) WaitForAuthentication(args interface{}, originator string) (*wallet.AuthenticatedResult, error) {
	resp, err := t.transmit(CallWaitForAuthentication, originator, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit wait for authentication call: %w", err)
	}
	return serializer.DeserializeAuthenticatedResult(resp)
}

func (t *WalletWireTransceiver) GetHeight(args interface{}, originator string) (*wallet.GetHeightResult, error) {
	resp, err := t.transmit(CallGetHeight, originator, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit get height call: %w", err)
	}
	return serializer.DeserializeGetHeightResult(resp)
}

func (t *WalletWireTransceiver) GetHeaderForHeight(args wallet.GetHeaderArgs, originator string) (*wallet.GetHeaderResult, error) {
	data, err := serializer.SerializeGetHeaderArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize get header arguments: %w", err)
	}
	resp, err := t.transmit(CallGetHeaderForHeight, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit get header call: %w", err)
	}
	return serializer.DeserializeGetHeaderResult(resp)
}

func (t *WalletWireTransceiver) GetNetwork(args interface{}, originator string) (*wallet.GetNetworkResult, error) {
	resp, err := t.transmit(CallGetNetwork, originator, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit get network call: %w", err)
	}
	return serializer.DeserializeGetNetworkResult(resp)
}

func (t *WalletWireTransceiver) GetVersion(args interface{}, originator string) (*wallet.GetVersionResult, error) {
	resp, err := t.transmit(CallGetVersion, originator, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit get version call: %w", err)
	}
	return serializer.DeserializeGetVersionResult(resp)
}
