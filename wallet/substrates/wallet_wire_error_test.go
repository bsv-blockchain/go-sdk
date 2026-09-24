package substrates_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/substrates"
)

const testWalletErrMsg = "wallet error"

// buildPairWithWalletError creates a transceiver pair where all wallet calls return an error.
func buildPairWithWalletError(t *testing.T) *substrates.WalletWireTransceiver {
	t.Helper()
	tw := wallet.NewTestWalletForRandomKey(t)
	errVal := errors.New(testWalletErrMsg)

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
	return substrates.NewWalletWireTransceiver(processor)
}

func TestTransceiverWalletErrorCreateAction(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	_, err := transceiver.CreateAction(context.Background(), wallet.CreateActionArgs{Description: "test"}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorSignAction(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	_, err := transceiver.SignAction(context.Background(), wallet.SignActionArgs{Reference: []byte("r")}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorAbortAction(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	_, err := transceiver.AbortAction(context.Background(), wallet.AbortActionArgs{Reference: []byte("r")}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorListActions(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	_, err := transceiver.ListActions(context.Background(), wallet.ListActionsArgs{}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorInternalizeAction(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	_, err := transceiver.InternalizeAction(context.Background(), wallet.InternalizeActionArgs{Tx: []byte{1}, Description: "d"}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorListOutputs(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	_, err := transceiver.ListOutputs(context.Background(), wallet.ListOutputsArgs{Basket: "b"}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorRelinquishOutput(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	_, err := transceiver.RelinquishOutput(context.Background(), wallet.RelinquishOutputArgs{Basket: "b"}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorGetPublicKey(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	_, err := transceiver.GetPublicKey(context.Background(), wallet.GetPublicKeyArgs{IdentityKey: true}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorListCertificates(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	_, err := transceiver.ListCertificates(context.Background(), wallet.ListCertificatesArgs{}, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorIsAuthenticated(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	_, err := transceiver.IsAuthenticated(context.Background(), nil, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorGetHeight(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	_, err := transceiver.GetHeight(context.Background(), nil, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorGetNetwork(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	_, err := transceiver.GetNetwork(context.Background(), nil, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

func TestTransceiverWalletErrorGetVersion(t *testing.T) {
	transceiver := buildPairWithWalletError(t)
	_, err := transceiver.GetVersion(context.Background(), nil, "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), testWalletErrMsg)
}

// TestTransceiverVerifySignatureInvalidSignaturePreservesSentinel is a
// round-trip check that wallet.ErrInvalidSignature (ProtoWallet.
// VerifySignature's exported sentinel for "the signature is cryptographically
// invalid", matching the TS reference's ERR_INVALID_SIGNATURE) survives being
// carried across Go's wallet wire substrate: WalletWireProcessor wrapping the
// underlying wallet call, and WalletWireTransceiver wrapping the round trip
// through the (in this test, in-process) Wire. A caller driving a wallet
// purely through this substrate must still be able to tell "the signature
// was invalid" apart from any other failure via errors.Is.
func TestTransceiverVerifySignatureInvalidSignaturePreservesSentinel(t *testing.T) {
	priv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	tw := wallet.NewTestWallet(t, priv)

	protocolID := wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "wire error test"}
	sigResult, err := tw.CreateSignature(context.Background(), wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID:   protocolID,
			KeyID:        "1",
			Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
		},
		Data: []byte("the actual signed message"),
	}, "")
	require.NoError(t, err)

	processor := substrates.NewWalletWireProcessor(tw)
	transceiver := substrates.NewWalletWireTransceiver(processor)

	// Verify against different data than was signed: a well-formed signature
	// that simply does not match, guaranteed to hit ProtoWallet's
	// ErrInvalidSignature path rather than a parse/format error.
	_, err = transceiver.VerifySignature(context.Background(), wallet.VerifySignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID:   protocolID,
			KeyID:        "1",
			Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
		},
		Data:      []byte("a different message entirely"),
		Signature: sigResult.Signature,
	}, "app")
	require.Error(t, err)
	require.ErrorIs(t, err, wallet.ErrInvalidSignature)
}

// TestTransceiverVerifyHMACInvalidHMACPreservesSentinel is the VerifyHMAC
// analog of the test above: wallet.ErrInvalidHMAC must also survive the
// same round trip.
func TestTransceiverVerifyHMACInvalidHMACPreservesSentinel(t *testing.T) {
	priv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	tw := wallet.NewTestWallet(t, priv)

	protocolID := wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "wire error test"}
	hmacResult, err := tw.CreateHMAC(context.Background(), wallet.CreateHMACArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID:   protocolID,
			KeyID:        "1",
			Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
		},
		Data: []byte("the actual authenticated message"),
	}, "")
	require.NoError(t, err)

	processor := substrates.NewWalletWireProcessor(tw)
	transceiver := substrates.NewWalletWireTransceiver(processor)

	_, err = transceiver.VerifyHMAC(context.Background(), wallet.VerifyHMACArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID:   protocolID,
			KeyID:        "1",
			Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
		},
		Data: []byte("a different message entirely"),
		HMAC: hmacResult.HMAC,
	}, "app")
	require.Error(t, err)
	require.ErrorIs(t, err, wallet.ErrInvalidHMAC)
}
