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
		response, err = w.processCreateAction(requestFrame)
	case CallSignAction:
		response, err = w.processSignAction(requestFrame)
	case CallAbortAction:
		response, err = w.processAbortAction(requestFrame)
	case CallListActions:
		response, err = w.processListActions(requestFrame)
	case CallInternalizeAction:
		response, err = w.processInternalizeAction(requestFrame)
	case CallListOutputs:
		response, err = w.processListOutputs(requestFrame)
	case CallGetPublicKey:
		response, err = w.processGetPublicKey(requestFrame)
	case CallRevealCounterpartyKeyLinkage:
		response, err = w.processRevealCounterpartyKeyLinkage(requestFrame)
	case CallRevealSpecificKeyLinkage:
		response, err = w.processRevealSpecificKeyLinkage(requestFrame)
	case CallEncrypt:
		response, err = w.processEncrypt(requestFrame)
	case CallDecrypt:
		response, err = w.processDecrypt(requestFrame)
	case CallCreateHmac:
		response, err = w.processCreateHmac(requestFrame)
	case CallVerifyHmac:
		response, err = w.processVerifyHmac(requestFrame)
	case CallCreateSignature:
		response, err = w.processCreateSignature(requestFrame)
	case CallVerifySignature:
		response, err = w.processVerifySignature(requestFrame)
	case CallAcquireCertificate:
		response, err = w.processAcquireCertificate(requestFrame)
	case CallListCertificates:
		response, err = w.processListCertificates(requestFrame)
	case CallProveCertificate:
		response, err = w.processProveCertificate(requestFrame)
	case CallRelinquishCertificate:
		response, err = w.processRelinquishCertificate(requestFrame)
	case CallDiscoverByIdentityKey:
		response, err = w.processDiscoverByIdentityKey(requestFrame)
	case CallDiscoverByAttributes:
		response, err = w.processDiscoverByAttributes(requestFrame)
	case CallIsAuthenticated:
		response, err = w.processIsAuthenticated(requestFrame)
	case CallWaitForAuthentication:
		response, err = w.processWaitForAuthentication(requestFrame)
	case CallGetHeight:
		response, err = w.processGetHeight(requestFrame)
	case CallGetHeaderForHeight:
		response, err = w.processGetHeaderForHeight(requestFrame)
	case CallGetNetwork:
		response, err = w.processGetNetwork(requestFrame)
	case CallGetVersion:
		response, err = w.processGetVersion(requestFrame)
	default:
		return nil, fmt.Errorf("unknown call type: %d", requestFrame.Call)
	}
	if err != nil {
		return nil, fmt.Errorf("error calling %d: %w", requestFrame.Call, err)
	}
	return serializer.WriteResultFrame(response, nil), nil
}

func (w *WalletWireProcessor) processSignAction(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeSignActionArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize sign action args: %w", err)
	}
	result, err := w.Wallet.SignAction(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process sign action: %w", err)
	}
	return serializer.SerializeSignActionResult(result)
}

func (w *WalletWireProcessor) processCreateAction(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeCreateActionArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize create action args: %w", err)
	}
	result, err := w.Wallet.CreateAction(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process create action: %w", err)
	}
	return serializer.SerializeCreateActionResult(result)
}

func (w *WalletWireProcessor) processAbortAction(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeAbortActionArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize abort action args: %w", err)
	}
	result, err := w.Wallet.AbortAction(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process abort action: %w", err)
	}
	return serializer.SerializeAbortActionResult(result)
}

func (w *WalletWireProcessor) processListActions(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeListActionsArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize list action args: %w", err)
	}
	result, err := w.Wallet.ListActions(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process list action: %w", err)
	}
	return serializer.SerializeListActionsResult(result)
}

func (w *WalletWireProcessor) processInternalizeAction(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeInternalizeActionArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to internalize list action args: %w", err)
	}
	result, err := w.Wallet.InternalizeAction(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process internalize action: %w", err)
	}
	return serializer.SerializeInternalizeActionResult(result)
}

func (w *WalletWireProcessor) processListOutputs(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeListOutputsArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize list outputs args: %w", err)
	}
	result, err := w.Wallet.ListOutputs(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process list outputs: %w", err)
	}
	return serializer.SerializeListOutputsResult(result)
}

func (w *WalletWireProcessor) processGetPublicKey(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeGetPublicKeyArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize get public key args: %w", err)
	}
	result, err := w.Wallet.GetPublicKey(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process get public key: %w", err)
	}
	return serializer.SerializeGetPublicKeyResult(result)
}

func (w *WalletWireProcessor) processRevealCounterpartyKeyLinkage(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeRevealCounterpartyKeyLinkageArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize reveal counterparty key linkage args: %w", err)
	}
	result, err := w.Wallet.RevealCounterpartyKeyLinkage(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process reveal counterparty key linkage: %w", err)
	}
	return serializer.SerializeRevealCounterpartyKeyLinkageResult(result)
}

func (w *WalletWireProcessor) processRevealSpecificKeyLinkage(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeRevealSpecificKeyLinkageArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize reveal specific key linkage args: %w", err)
	}
	result, err := w.Wallet.RevealSpecificKeyLinkage(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process reveal specific key linkage: %w", err)
	}
	return serializer.SerializeRevealSpecificKeyLinkageResult(result)
}

func (w *WalletWireProcessor) processEncrypt(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeEncryptArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize encrypt args: %w", err)
	}
	result, err := w.Wallet.Encrypt(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process encrypt: %w", err)
	}
	return serializer.SerializeEncryptResult(result)
}

func (w *WalletWireProcessor) processDecrypt(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeDecryptArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize decrypt args: %w", err)
	}
	result, err := w.Wallet.Decrypt(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process decrypt: %w", err)
	}
	return serializer.SerializeDecryptResult(result)
}

func (w *WalletWireProcessor) processCreateHmac(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeCreateHmacArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize create hmac args: %w", err)
	}
	result, err := w.Wallet.CreateHmac(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process create hmac: %w", err)
	}
	return serializer.SerializeCreateHmacResult(result)
}

func (w *WalletWireProcessor) processVerifyHmac(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeVerifyHmacArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize verify hmac args: %w", err)
	}
	result, err := w.Wallet.VerifyHmac(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process verify hmac: %w", err)
	}
	return serializer.SerializeVerifyHmacResult(result)
}

func (w *WalletWireProcessor) processCreateSignature(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeCreateSignatureArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize create signature args: %w", err)
	}
	result, err := w.Wallet.CreateSignature(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process create signature: %w", err)
	}
	return serializer.SerializeCreateSignatureResult(result)
}

func (w *WalletWireProcessor) processVerifySignature(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeVerifySignatureArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize verify signature args: %w", err)
	}
	result, err := w.Wallet.VerifySignature(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process verify signature: %w", err)
	}
	return serializer.SerializeVerifySignatureResult(result)
}

func (w *WalletWireProcessor) processAcquireCertificate(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeAcquireCertificateArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize acquire certificate args: %w", err)
	}
	result, err := w.Wallet.AcquireCertificate(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process acquire certificate: %w", err)
	}
	return serializer.SerializeCertificate(result)
}

func (w *WalletWireProcessor) processListCertificates(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeListCertificatesArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize list certificates args: %w", err)
	}
	result, err := w.Wallet.ListCertificates(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process list certificates: %w", err)
	}
	return serializer.SerializeListCertificatesResult(result)
}

func (w *WalletWireProcessor) processProveCertificate(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeProveCertificateArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize prove certificate args: %w", err)
	}
	result, err := w.Wallet.ProveCertificate(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process prove certificate: %w", err)
	}
	return serializer.SerializeProveCertificateResult(result)
}

func (w *WalletWireProcessor) processRelinquishCertificate(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeRelinquishCertificateArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize relinquish certificate args: %w", err)
	}
	result, err := w.Wallet.RelinquishCertificate(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process relinquish certificate: %w", err)
	}
	return serializer.SerializeRelinquishCertificateResult(result)
}

func (w *WalletWireProcessor) processDiscoverByIdentityKey(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeDiscoverByIdentityKeyArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize discover by identity key args: %w", err)
	}
	result, err := w.Wallet.DiscoverByIdentityKey(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process discover by identity key: %w", err)
	}
	return serializer.SerializeDiscoverCertificatesResult(result)
}

func (w *WalletWireProcessor) processDiscoverByAttributes(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeDiscoverByAttributesArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize discover by attributes args: %w", err)
	}
	result, err := w.Wallet.DiscoverByAttributes(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process discover by attributes: %w", err)
	}
	return serializer.SerializeDiscoverCertificatesResult(result)
}

func (w *WalletWireProcessor) processIsAuthenticated(requestFrame *serializer.RequestFrame) ([]byte, error) {
	result, err := w.Wallet.IsAuthenticated(nil, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process is authenticated: %w", err)
	}
	return serializer.SerializeAuthenticatedResult(result)
}

func (w *WalletWireProcessor) processWaitForAuthentication(requestFrame *serializer.RequestFrame) ([]byte, error) {
	result, err := w.Wallet.WaitForAuthentication(nil, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process wait for authentication: %w", err)
	}
	return serializer.SerializeAuthenticatedResult(result)
}

func (w *WalletWireProcessor) processGetHeight(requestFrame *serializer.RequestFrame) ([]byte, error) {
	result, err := w.Wallet.GetHeight(nil, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process get height: %w", err)
	}
	return serializer.SerializeGetHeightResult(result)
}

func (w *WalletWireProcessor) processGetHeaderForHeight(requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeGetHeaderArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize get header args: %w", err)
	}
	result, err := w.Wallet.GetHeaderForHeight(*args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process get header for height: %w", err)
	}
	return serializer.SerializeGetHeaderResult(result)
}

func (w *WalletWireProcessor) processGetNetwork(requestFrame *serializer.RequestFrame) ([]byte, error) {
	result, err := w.Wallet.GetNetwork(nil, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process get network: %w", err)
	}
	return serializer.SerializeGetNetworkResult(result)
}

func (w *WalletWireProcessor) processGetVersion(requestFrame *serializer.RequestFrame) ([]byte, error) {
	result, err := w.Wallet.GetVersion(nil, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process get version: %w", err)
	}
	return serializer.SerializeGetVersionResult(result)
}
