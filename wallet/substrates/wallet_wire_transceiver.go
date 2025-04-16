package substrates

import (
	"context"
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

func (t *WalletWireTransceiver) transmit(ctx context.Context, call Call, originator string, params []byte) ([]byte, error) {
	// Create frame
	frame := serializer.WriteRequestFrame(serializer.RequestFrame{
		Call:       byte(call),
		Originator: originator,
		Params:     params,
	})

	// Transmit frame to processor
	result, err := t.Wire.TransmitToWallet(ctx, frame)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit call to wallet wire: %w", err)
	}

	// Parse response
	return serializer.ReadResultFrame(result)
}

func (t *WalletWireTransceiver) CreateAction(ctx context.Context, args wallet.CreateActionArgs, originator string) (*wallet.CreateActionResult, error) {
	// Serialize the request
	data, err := serializer.SerializeCreateActionArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize create action arguments: %w", err)
	}

	// Send to processor
	resp, err := t.transmit(ctx, CallCreateAction, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit create action call: %w", err)
	}

	// Deserialize response
	return serializer.DeserializeCreateActionResult(resp)
}

func (t *WalletWireTransceiver) SignAction(ctx context.Context, args wallet.SignActionArgs, originator string) (*wallet.SignActionResult, error) {
	// Serialize the request
	data, err := serializer.SerializeSignActionArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize sign action arguments: %w", err)
	}

	// Send to processor
	resp, err := t.transmit(ctx, CallSignAction, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit sign action call: %w", err)
	}

	// Deserialize response
	return serializer.DeserializeSignActionResult(resp)
}

func (t *WalletWireTransceiver) AbortAction(ctx context.Context, args wallet.AbortActionArgs, originator string) (*wallet.AbortActionResult, error) {
	// Serialize the request
	data, err := serializer.SerializeAbortActionArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize abort action arguments: %w", err)
	}

	// Send to processor
	resp, err := t.transmit(ctx, CallAbortAction, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit abort action call: %w", err)
	}

	// Deserialize response
	return serializer.DeserializeAbortActionResult(resp)
}

func (t *WalletWireTransceiver) ListActions(ctx context.Context, args wallet.ListActionsArgs, originator string) (*wallet.ListActionsResult, error) {
	// Serialize the request
	data, err := serializer.SerializeListActionsArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize list action arguments: %w", err)
	}

	// Send to processor
	resp, err := t.transmit(ctx, CallListActions, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit list action call: %w", err)
	}

	// Deserialize response
	return serializer.DeserializeListActionsResult(resp)
}

func (t *WalletWireTransceiver) InternalizeAction(ctx context.Context, args wallet.InternalizeActionArgs, originator string) (*wallet.InternalizeActionResult, error) {
	// Serialize the request
	data, err := serializer.SerializeInternalizeActionArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize internalize action arguments: %w", err)
	}

	// Send to processor
	resp, err := t.transmit(ctx, CallInternalizeAction, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit internalize action call: %w", err)
	}

	// Deserialize response
	return serializer.DeserializeInternalizeActionResult(resp)
}

func (t *WalletWireTransceiver) ListOutputs(ctx context.Context, args wallet.ListOutputsArgs, originator string) (*wallet.ListOutputsResult, error) {
	// Serialize the request
	data, err := serializer.SerializeListOutputsArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize list outputs arguments: %w", err)
	}

	// Send to processor
	resp, err := t.transmit(ctx, CallListOutputs, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit list outputs call: %w", err)
	}

	// Deserialize response
	return serializer.DeserializeListOutputsResult(resp)
}

func (t *WalletWireTransceiver) RelinquishOutput(ctx context.Context, args wallet.RelinquishOutputArgs, originator string) (*wallet.RelinquishOutputResult, error) {
	data, err := serializer.SerializeRelinquishOutputArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize relinquish output arguments: %w", err)
	}
	resp, err := t.transmit(ctx, CallRelinquishOutput, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit relinquish output call: %w", err)
	}
	return serializer.DeserializeRelinquishOutputResult(resp)
}

func (t *WalletWireTransceiver) GetPublicKey(ctx context.Context, args wallet.GetPublicKeyArgs, originator string) (*wallet.GetPublicKeyResult, error) {
	data, err := serializer.SerializeGetPublicKeyArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize get public key arguments: %w", err)
	}
	resp, err := t.transmit(ctx, CallGetPublicKey, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit get public key call: %w", err)
	}
	return serializer.DeserializeGetPublicKeyResult(resp)
}

func (t *WalletWireTransceiver) RevealCounterpartyKeyLinkage(ctx context.Context, args wallet.RevealCounterpartyKeyLinkageArgs, originator string) (*wallet.RevealCounterpartyKeyLinkageResult, error) {
	data, err := serializer.SerializeRevealCounterpartyKeyLinkageArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize reveal counterparty key linkage arguments: %w", err)
	}
	resp, err := t.transmit(ctx, CallRevealCounterpartyKeyLinkage, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit reveal counterparty key linkage call: %w", err)
	}
	return serializer.DeserializeRevealCounterpartyKeyLinkageResult(resp)
}

func (t *WalletWireTransceiver) RevealSpecificKeyLinkage(ctx context.Context, args wallet.RevealSpecificKeyLinkageArgs, originator string) (*wallet.RevealSpecificKeyLinkageResult, error) {
	data, err := serializer.SerializeRevealSpecificKeyLinkageArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize reveal specific key linkage arguments: %w", err)
	}
	resp, err := t.transmit(ctx, CallRevealSpecificKeyLinkage, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit reveal specific key linkage call: %w", err)
	}
	return serializer.DeserializeRevealSpecificKeyLinkageResult(resp)
}

func (t *WalletWireTransceiver) Encrypt(ctx context.Context, args wallet.EncryptArgs, originator string) (*wallet.EncryptResult, error) {
	data, err := serializer.SerializeEncryptArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize encrypt arguments: %w", err)
	}
	resp, err := t.transmit(ctx, CallEncrypt, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit encrypt call: %w", err)
	}
	return serializer.DeserializeEncryptResult(resp)
}

func (t *WalletWireTransceiver) Decrypt(ctx context.Context, args wallet.DecryptArgs, originator string) (*wallet.DecryptResult, error) {
	data, err := serializer.SerializeDecryptArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize decrypt arguments: %w", err)
	}
	resp, err := t.transmit(ctx, CallDecrypt, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit decrypt call: %w", err)
	}
	return serializer.DeserializeDecryptResult(resp)
}

func (t *WalletWireTransceiver) CreateHmac(ctx context.Context, args wallet.CreateHmacArgs, originator string) (*wallet.CreateHmacResult, error) {
	data, err := serializer.SerializeCreateHmacArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize create hmac arguments: %w", err)
	}
	resp, err := t.transmit(ctx, CallCreateHmac, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit create hmac call: %w", err)
	}
	return serializer.DeserializeCreateHmacResult(resp)
}

func (t *WalletWireTransceiver) VerifyHmac(ctx context.Context, args wallet.VerifyHmacArgs, originator string) (*wallet.VerifyHmacResult, error) {
	data, err := serializer.SerializeVerifyHmacArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize verify hmac arguments: %w", err)
	}
	resp, err := t.transmit(ctx, CallVerifyHmac, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit verify hmac call: %w", err)
	}
	return serializer.DeserializeVerifyHmacResult(resp)
}

func (t *WalletWireTransceiver) CreateSignature(ctx context.Context, args wallet.CreateSignatureArgs, originator string) (*wallet.CreateSignatureResult, error) {
	data, err := serializer.SerializeCreateSignatureArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize create signature arguments: %w", err)
	}
	resp, err := t.transmit(ctx, CallCreateSignature, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit create signature call: %w", err)
	}
	return serializer.DeserializeCreateSignatureResult(resp)
}

func (t *WalletWireTransceiver) VerifySignature(ctx context.Context, args wallet.VerifySignatureArgs, originator string) (*wallet.VerifySignatureResult, error) {
	data, err := serializer.SerializeVerifySignatureArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize verify signature arguments: %w", err)
	}
	resp, err := t.transmit(ctx, CallVerifySignature, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit verify signature call: %w", err)
	}
	return serializer.DeserializeVerifySignatureResult(resp)
}

func (t *WalletWireTransceiver) AcquireCertificate(ctx context.Context, args wallet.AcquireCertificateArgs, originator string) (*wallet.Certificate, error) {
	data, err := serializer.SerializeAcquireCertificateArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize acquire certificate arguments: %w", err)
	}
	resp, err := t.transmit(ctx, CallAcquireCertificate, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit acquire certificate call: %w", err)
	}
	return serializer.DeserializeCertificate(resp)
}

func (t *WalletWireTransceiver) ListCertificates(ctx context.Context, args wallet.ListCertificatesArgs, originator string) (*wallet.ListCertificatesResult, error) {
	data, err := serializer.SerializeListCertificatesArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize list certificates arguments: %w", err)
	}
	resp, err := t.transmit(ctx, CallListCertificates, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit list certificates call: %w", err)
	}
	return serializer.DeserializeListCertificatesResult(resp)
}

func (t *WalletWireTransceiver) ProveCertificate(ctx context.Context, args wallet.ProveCertificateArgs, originator string) (*wallet.ProveCertificateResult, error) {
	data, err := serializer.SerializeProveCertificateArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize prove certificate arguments: %w", err)
	}
	resp, err := t.transmit(ctx, CallProveCertificate, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit prove certificate call: %w", err)
	}
	return serializer.DeserializeProveCertificateResult(resp)
}

func (t *WalletWireTransceiver) RelinquishCertificate(ctx context.Context, args wallet.RelinquishCertificateArgs, originator string) (*wallet.RelinquishCertificateResult, error) {
	data, err := serializer.SerializeRelinquishCertificateArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize relinquish certificate arguments: %w", err)
	}
	resp, err := t.transmit(ctx, CallRelinquishCertificate, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit relinquish certificate call: %w", err)
	}
	return serializer.DeserializeRelinquishCertificateResult(resp)
}

func (t *WalletWireTransceiver) DiscoverByIdentityKey(ctx context.Context, args wallet.DiscoverByIdentityKeyArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	data, err := serializer.SerializeDiscoverByIdentityKeyArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize discover by identity key arguments: %w", err)
	}
	resp, err := t.transmit(ctx, CallDiscoverByIdentityKey, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit discover by identity key call: %w", err)
	}
	return serializer.DeserializeDiscoverCertificatesResult(resp)
}

func (t *WalletWireTransceiver) DiscoverByAttributes(ctx context.Context, args wallet.DiscoverByAttributesArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	data, err := serializer.SerializeDiscoverByAttributesArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize discover by attributes arguments: %w", err)
	}
	resp, err := t.transmit(ctx, CallDiscoverByAttributes, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit discover by attributes call: %w", err)
	}
	return serializer.DeserializeDiscoverCertificatesResult(resp)
}

func (t *WalletWireTransceiver) IsAuthenticated(ctx context.Context, args interface{}, originator string) (*wallet.AuthenticatedResult, error) {
	resp, err := t.transmit(ctx, CallIsAuthenticated, originator, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit is authenticated call: %w", err)
	}
	return serializer.DeserializeAuthenticatedResult(resp)
}

func (t *WalletWireTransceiver) WaitForAuthentication(ctx context.Context, args interface{}, originator string) (*wallet.AuthenticatedResult, error) {
	resp, err := t.transmit(ctx, CallWaitForAuthentication, originator, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit wait for authentication call: %w", err)
	}
	return serializer.DeserializeAuthenticatedResult(resp)
}

func (t *WalletWireTransceiver) GetHeight(ctx context.Context, args interface{}, originator string) (*wallet.GetHeightResult, error) {
	resp, err := t.transmit(ctx, CallGetHeight, originator, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit get height call: %w", err)
	}
	return serializer.DeserializeGetHeightResult(resp)
}

func (t *WalletWireTransceiver) GetHeaderForHeight(ctx context.Context, args wallet.GetHeaderArgs, originator string) (*wallet.GetHeaderResult, error) {
	data, err := serializer.SerializeGetHeaderArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize get header arguments: %w", err)
	}
	resp, err := t.transmit(ctx, CallGetHeaderForHeight, originator, data)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit get header call: %w", err)
	}
	return serializer.DeserializeGetHeaderResult(resp)
}

func (t *WalletWireTransceiver) GetNetwork(ctx context.Context, args interface{}, originator string) (*wallet.GetNetworkResult, error) {
	resp, err := t.transmit(ctx, CallGetNetwork, originator, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit get network call: %w", err)
	}
	return serializer.DeserializeGetNetworkResult(resp)
}

func (t *WalletWireTransceiver) GetVersion(ctx context.Context, args interface{}, originator string) (*wallet.GetVersionResult, error) {
	resp, err := t.transmit(ctx, CallGetVersion, originator, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to transmit get version call: %w", err)
	}
	return serializer.DeserializeGetVersionResult(resp)
}
