package substrates

import (
	"context"
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

func (w *WalletWireProcessor) TransmitToWallet(ctx context.Context, message []byte) ([]byte, error) {
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
		response, err = w.processCreateAction(ctx, requestFrame)
	case CallSignAction:
		response, err = w.processSignAction(ctx, requestFrame)
	case CallAbortAction:
		response, err = w.processAbortAction(ctx, requestFrame)
	case CallListActions:
		response, err = w.processListActions(ctx, requestFrame)
	case CallInternalizeAction:
		response, err = w.processInternalizeAction(ctx, requestFrame)
	case CallListOutputs:
		response, err = w.processListOutputs(ctx, requestFrame)
	case CallRelinquishOutput:
		response, err = w.processRelinquishOutput(ctx, requestFrame)
	case CallGetPublicKey:
		response, err = w.processGetPublicKey(ctx, requestFrame)
	case CallRevealCounterpartyKeyLinkage:
		response, err = w.processRevealCounterpartyKeyLinkage(ctx, requestFrame)
	case CallRevealSpecificKeyLinkage:
		response, err = w.processRevealSpecificKeyLinkage(ctx, requestFrame)
	case CallEncrypt:
		response, err = w.processEncrypt(ctx, requestFrame)
	case CallDecrypt:
		response, err = w.processDecrypt(ctx, requestFrame)
	case CallCreateHMAC:
		response, err = w.processCreateHMAC(ctx, requestFrame)
	case CallVerifyHMAC:
		response, err = w.processVerifyHMAC(ctx, requestFrame)
	case CallCreateSignature:
		response, err = w.processCreateSignature(ctx, requestFrame)
	case CallVerifySignature:
		response, err = w.processVerifySignature(ctx, requestFrame)
	case CallAcquireCertificate:
		response, err = w.processAcquireCertificate(ctx, requestFrame)
	case CallListCertificates:
		response, err = w.processListCertificates(ctx, requestFrame)
	case CallProveCertificate:
		response, err = w.processProveCertificate(ctx, requestFrame)
	case CallRelinquishCertificate:
		response, err = w.processRelinquishCertificate(ctx, requestFrame)
	case CallDiscoverByIdentityKey:
		response, err = w.processDiscoverByIdentityKey(ctx, requestFrame)
	case CallDiscoverByAttributes:
		response, err = w.processDiscoverByAttributes(ctx, requestFrame)
	case CallIsAuthenticated:
		response, err = w.processIsAuthenticated(ctx, requestFrame)
	case CallWaitForAuthentication:
		response, err = w.processWaitForAuthentication(ctx, requestFrame)
	case CallGetHeight:
		response, err = w.processGetHeight(ctx, requestFrame)
	case CallGetHeaderForHeight:
		response, err = w.processGetHeaderForHeight(ctx, requestFrame)
	case CallGetNetwork:
		response, err = w.processGetNetwork(ctx, requestFrame)
	case CallGetVersion:
		response, err = w.processGetVersion(ctx, requestFrame)
	default:
		return nil, fmt.Errorf("unknown call type: %d", requestFrame.Call)
	}
	if err != nil {
		return nil, fmt.Errorf("error calling %d: %w", requestFrame.Call, err)
	}
	return serializer.WriteResultFrame(response, nil), nil
}

func (w *WalletWireProcessor) processSignAction(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeSignActionArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize sign action args: %w", err)
	}
	result, err := w.Wallet.SignAction(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process sign action: %w", err)
	}
	return serializer.SerializeSignActionResult(result)
}

func (w *WalletWireProcessor) processCreateAction(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeCreateActionArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize create action args: %w", err)
	}
	result, err := w.Wallet.CreateAction(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process create action: %w", err)
	}
	return serializer.SerializeCreateActionResult(result)
}

func (w *WalletWireProcessor) processAbortAction(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeAbortActionArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize abort action args: %w", err)
	}
	result, err := w.Wallet.AbortAction(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process abort action: %w", err)
	}
	return serializer.SerializeAbortActionResult(result)
}

func (w *WalletWireProcessor) processListActions(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeListActionsArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize list action args: %w", err)
	}
	result, err := w.Wallet.ListActions(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process list action: %w", err)
	}
	return serializer.SerializeListActionsResult(result)
}

func (w *WalletWireProcessor) processInternalizeAction(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeInternalizeActionArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to internalize list action args: %w", err)
	}
	result, err := w.Wallet.InternalizeAction(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process internalize action: %w", err)
	}
	return serializer.SerializeInternalizeActionResult(result)
}

func (w *WalletWireProcessor) processListOutputs(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeListOutputsArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize list outputs args: %w", err)
	}
	result, err := w.Wallet.ListOutputs(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process list outputs: %w", err)
	}
	return serializer.SerializeListOutputsResult(result)
}

func (w *WalletWireProcessor) processRelinquishOutput(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeRelinquishOutputArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize relinquish output args: %w", err)
	}
	result, err := w.Wallet.RelinquishOutput(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process relinquish output: %w", err)
	}
	return serializer.SerializeRelinquishOutputResult(result)
}

func (w *WalletWireProcessor) processGetPublicKey(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeGetPublicKeyArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize get public key args: %w", err)
	}
	result, err := w.Wallet.GetPublicKey(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process get public key: %w", err)
	}
	return serializer.SerializeGetPublicKeyResult(result)
}

func (w *WalletWireProcessor) processRevealCounterpartyKeyLinkage(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeRevealCounterpartyKeyLinkageArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize reveal counterparty key linkage args: %w", err)
	}
	result, err := w.Wallet.RevealCounterpartyKeyLinkage(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process reveal counterparty key linkage: %w", err)
	}
	return serializer.SerializeRevealCounterpartyKeyLinkageResult(result)
}

func (w *WalletWireProcessor) processRevealSpecificKeyLinkage(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeRevealSpecificKeyLinkageArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize reveal specific key linkage args: %w", err)
	}
	result, err := w.Wallet.RevealSpecificKeyLinkage(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process reveal specific key linkage: %w", err)
	}
	return serializer.SerializeRevealSpecificKeyLinkageResult(result)
}

func (w *WalletWireProcessor) processEncrypt(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeEncryptArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize encrypt args: %w", err)
	}
	result, err := w.Wallet.Encrypt(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process encrypt: %w", err)
	}
	return serializer.SerializeEncryptResult(result)
}

func (w *WalletWireProcessor) processDecrypt(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeDecryptArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize decrypt args: %w", err)
	}
	result, err := w.Wallet.Decrypt(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process decrypt: %w", err)
	}
	return serializer.SerializeDecryptResult(result)
}

func (w *WalletWireProcessor) processCreateHMAC(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeCreateHMACArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize create hmac args: %w", err)
	}
	result, err := w.Wallet.CreateHMAC(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process create hmac: %w", err)
	}
	return serializer.SerializeCreateHMACResult(result)
}

func (w *WalletWireProcessor) processVerifyHMAC(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeVerifyHMACArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize verify hmac args: %w", err)
	}
	result, err := w.Wallet.VerifyHMAC(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process verify hmac: %w", err)
	}
	return serializer.SerializeVerifyHMACResult(result)
}

func (w *WalletWireProcessor) processCreateSignature(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeCreateSignatureArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize create signature args: %w", err)
	}
	result, err := w.Wallet.CreateSignature(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process create signature: %w", err)
	}
	return serializer.SerializeCreateSignatureResult(result)
}

func (w *WalletWireProcessor) processVerifySignature(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeVerifySignatureArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize verify signature args: %w", err)
	}
	result, err := w.Wallet.VerifySignature(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process verify signature: %w", err)
	}
	return serializer.SerializeVerifySignatureResult(result)
}

func (w *WalletWireProcessor) processAcquireCertificate(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeAcquireCertificateArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize acquire certificate args: %w", err)
	}
	result, err := w.Wallet.AcquireCertificate(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process acquire certificate: %w", err)
	}
	return serializer.SerializeCertificate(result)
}

func (w *WalletWireProcessor) processListCertificates(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeListCertificatesArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize list certificates args: %w", err)
	}
	result, err := w.Wallet.ListCertificates(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process list certificates: %w", err)
	}
	return serializer.SerializeListCertificatesResult(result)
}

func (w *WalletWireProcessor) processProveCertificate(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeProveCertificateArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize prove certificate args: %w", err)
	}
	result, err := w.Wallet.ProveCertificate(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process prove certificate: %w", err)
	}
	return serializer.SerializeProveCertificateResult(result)
}

func (w *WalletWireProcessor) processRelinquishCertificate(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeRelinquishCertificateArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize relinquish certificate args: %w", err)
	}
	result, err := w.Wallet.RelinquishCertificate(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process relinquish certificate: %w", err)
	}
	return serializer.SerializeRelinquishCertificateResult(result)
}

func (w *WalletWireProcessor) processDiscoverByIdentityKey(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeDiscoverByIdentityKeyArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize discover by identity key args: %w", err)
	}
	result, err := w.Wallet.DiscoverByIdentityKey(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process discover by identity key: %w", err)
	}
	return serializer.SerializeDiscoverCertificatesResult(result)
}

func (w *WalletWireProcessor) processDiscoverByAttributes(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeDiscoverByAttributesArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize discover by attributes args: %w", err)
	}
	result, err := w.Wallet.DiscoverByAttributes(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process discover by attributes: %w", err)
	}
	return serializer.SerializeDiscoverCertificatesResult(result)
}

func (w *WalletWireProcessor) processIsAuthenticated(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	result, err := w.Wallet.IsAuthenticated(ctx, nil, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process is authenticated: %w", err)
	}
	return serializer.SerializeAuthenticatedResult(result)
}

func (w *WalletWireProcessor) processWaitForAuthentication(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	result, err := w.Wallet.WaitForAuthentication(ctx, nil, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process wait for authentication: %w", err)
	}
	return serializer.SerializeAuthenticatedResult(result)
}

func (w *WalletWireProcessor) processGetHeight(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	result, err := w.Wallet.GetHeight(ctx, nil, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process get height: %w", err)
	}
	return serializer.SerializeGetHeightResult(result)
}

func (w *WalletWireProcessor) processGetHeaderForHeight(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	args, err := serializer.DeserializeGetHeaderArgs(requestFrame.Params)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize get header args: %w", err)
	}
	result, err := w.Wallet.GetHeaderForHeight(ctx, *args, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process get header for height: %w", err)
	}
	return serializer.SerializeGetHeaderResult(result)
}

func (w *WalletWireProcessor) processGetNetwork(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	result, err := w.Wallet.GetNetwork(ctx, nil, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process get network: %w", err)
	}
	return serializer.SerializeGetNetworkResult(result)
}

func (w *WalletWireProcessor) processGetVersion(ctx context.Context, requestFrame *serializer.RequestFrame) ([]byte, error) {
	result, err := w.Wallet.GetVersion(ctx, nil, requestFrame.Originator)
	if err != nil {
		return nil, fmt.Errorf("failed to process get version: %w", err)
	}
	return serializer.SerializeGetVersionResult(result)
}
