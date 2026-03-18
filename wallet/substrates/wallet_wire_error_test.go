package substrates_test

import (
	"context"
	"errors"
	"testing"

	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/substrates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildPairWithWalletError creates a transceiver pair where all wallet calls return an error.
func buildPairWithWalletError(t *testing.T, errMsg string) (*wallet.TestWallet, *substrates.WalletWireTransceiver) {
	t.Helper()
	tw := wallet.NewTestWalletForRandomKey(t)
	errVal := errors.New(errMsg)

	tw.OnCreateAction().ReturnError(errVal)
	tw.OnSignAction().ReturnError(errVal)
	tw.OnAbortAction().ReturnError(errVal)
	tw.OnListActions().ReturnError(errVal)
	tw.OnInternalizeAction().ReturnError(errVal)
	tw.OnListOutputs().ReturnError(errVal)
	tw.OnRelinquishOutput().ReturnError(errVal)
	tw.OnGetPublicKey().ReturnError(errVal)
	tw.OnRevealCounterpartyKeyLinkage().ReturnError(errVal)
	tw.OnRevealSpecificKeyLinkage().ReturnError(errVal)
	tw.OnEncrypt().ReturnError(errVal)
	tw.OnDecrypt().ReturnError(errVal)
	tw.OnCreateHMAC().ReturnError(errVal)
	tw.OnVerifyHMAC().ReturnError(errVal)
	tw.OnCreateSignature().ReturnError(errVal)
	tw.OnVerifySignature().ReturnError(errVal)
	tw.OnAcquireCertificate().ReturnError(errVal)
	tw.OnListCertificates().ReturnError(errVal)
	tw.OnProveCertificate().ReturnError(errVal)
	tw.OnRelinquishCertificate().ReturnError(errVal)
	tw.OnDiscoverByIdentityKey().ReturnError(errVal)
	tw.OnDiscoverByAttributes().ReturnError(errVal)
	tw.OnIsAuthenticated().ReturnError(errVal)
	tw.OnWaitForAuthentication().ReturnError(errVal)
	tw.OnGetHeight().ReturnError(errVal)
	tw.OnGetHeaderForHeight().ReturnError(errVal)
	tw.OnGetNetwork().ReturnError(errVal)
	tw.OnGetVersion().ReturnError(errVal)

	processor := substrates.NewWalletWireProcessor(tw)
	transceiver := substrates.NewWalletWireTransceiver(processor)
	return tw, transceiver
}

func TestTransceiver_WalletError_CreateAction(t *testing.T) {
	_, transceiver := buildPairWithWalletError(t, "wallet error")
	_, err := transceiver.CreateAction(context.Background(), wallet.CreateActionArgs{Description: "test"}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wallet error")
}

func TestTransceiver_WalletError_SignAction(t *testing.T) {
	_, transceiver := buildPairWithWalletError(t, "wallet error")
	_, err := transceiver.SignAction(context.Background(), wallet.SignActionArgs{Reference: []byte("r")}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wallet error")
}

func TestTransceiver_WalletError_AbortAction(t *testing.T) {
	_, transceiver := buildPairWithWalletError(t, "wallet error")
	_, err := transceiver.AbortAction(context.Background(), wallet.AbortActionArgs{Reference: []byte("r")}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wallet error")
}

func TestTransceiver_WalletError_ListActions(t *testing.T) {
	_, transceiver := buildPairWithWalletError(t, "wallet error")
	_, err := transceiver.ListActions(context.Background(), wallet.ListActionsArgs{}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wallet error")
}

func TestTransceiver_WalletError_InternalizeAction(t *testing.T) {
	_, transceiver := buildPairWithWalletError(t, "wallet error")
	_, err := transceiver.InternalizeAction(context.Background(), wallet.InternalizeActionArgs{Tx: []byte{1}, Description: "d"}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wallet error")
}

func TestTransceiver_WalletError_ListOutputs(t *testing.T) {
	_, transceiver := buildPairWithWalletError(t, "wallet error")
	_, err := transceiver.ListOutputs(context.Background(), wallet.ListOutputsArgs{Basket: "b"}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wallet error")
}

func TestTransceiver_WalletError_RelinquishOutput(t *testing.T) {
	_, transceiver := buildPairWithWalletError(t, "wallet error")
	_, err := transceiver.RelinquishOutput(context.Background(), wallet.RelinquishOutputArgs{Basket: "b"}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wallet error")
}

func TestTransceiver_WalletError_GetPublicKey(t *testing.T) {
	_, transceiver := buildPairWithWalletError(t, "wallet error")
	_, err := transceiver.GetPublicKey(context.Background(), wallet.GetPublicKeyArgs{IdentityKey: true}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wallet error")
}

func TestTransceiver_WalletError_ListCertificates(t *testing.T) {
	_, transceiver := buildPairWithWalletError(t, "wallet error")
	_, err := transceiver.ListCertificates(context.Background(), wallet.ListCertificatesArgs{}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wallet error")
}

func TestTransceiver_WalletError_IsAuthenticated(t *testing.T) {
	_, transceiver := buildPairWithWalletError(t, "wallet error")
	_, err := transceiver.IsAuthenticated(context.Background(), nil, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wallet error")
}

func TestTransceiver_WalletError_GetHeight(t *testing.T) {
	_, transceiver := buildPairWithWalletError(t, "wallet error")
	_, err := transceiver.GetHeight(context.Background(), nil, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wallet error")
}

func TestTransceiver_WalletError_GetNetwork(t *testing.T) {
	_, transceiver := buildPairWithWalletError(t, "wallet error")
	_, err := transceiver.GetNetwork(context.Background(), nil, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wallet error")
}

func TestTransceiver_WalletError_GetVersion(t *testing.T) {
	_, transceiver := buildPairWithWalletError(t, "wallet error")
	_, err := transceiver.GetVersion(context.Background(), nil, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wallet error")
}
