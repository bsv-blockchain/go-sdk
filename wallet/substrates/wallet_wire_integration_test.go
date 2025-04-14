package substrates

import (
	"encoding/hex"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/serializer"
	"github.com/stretchr/testify/require"
	"testing"
)

type MockWallet struct {
	T                          *testing.T
	ExpectedOriginator         string
	ExpectedCreateActionArgs   *wallet.CreateActionArgs
	CreateActionResultToReturn *wallet.CreateActionResult
}

func NewMockWallet(t *testing.T) *MockWallet {
	return &MockWallet{T: t}
}

func (m *MockWallet) CreateAction(args wallet.CreateActionArgs, originator string) (*wallet.CreateActionResult, error) {
	if m.ExpectedCreateActionArgs != nil {
		require.Equal(m.T, m.ExpectedCreateActionArgs.Description, args.Description)
		require.Equal(m.T, m.ExpectedCreateActionArgs.Outputs, args.Outputs)
		require.Equal(m.T, m.ExpectedCreateActionArgs.Labels, args.Labels)
	}
	require.Equal(m.T, m.ExpectedOriginator, originator)
	return m.CreateActionResultToReturn, nil
}

func (m *MockWallet) SignAction(args wallet.SignActionArgs, originator string) (*wallet.SignActionResult, error) {
	require.Fail(m.T, "SignAction mock not implemented")
	return nil, nil
}

func (m *MockWallet) AbortAction(args wallet.AbortActionArgs, originator string) (*wallet.AbortActionResult, error) {
	require.Fail(m.T, "AbortAction mock not implemented")
	return nil, nil
}

func (m *MockWallet) ListActions(args wallet.ListActionsArgs, originator string) (*wallet.ListActionsResult, error) {
	require.Fail(m.T, "ListActions mock not implemented")
	return nil, nil
}

func (m *MockWallet) InternalizeAction(args wallet.InternalizeActionArgs, originator string) (*wallet.InternalizeActionResult, error) {
	require.Fail(m.T, "InternalizeAction mock not implemented")
	return nil, nil
}

func (m *MockWallet) ListOutputs(args wallet.ListOutputsArgs, originator string) (*wallet.ListOutputsResult, error) {
	require.Fail(m.T, "ListOutputs mock not implemented")
	return nil, nil
}

func (m *MockWallet) RelinquishOutput(args wallet.RelinquishOutputArgs, originator string) (*wallet.RelinquishOutputResult, error) {
	require.Fail(m.T, "RelinquishOutput mock not implemented")
	return nil, nil
}

func (m *MockWallet) GetPublicKey(args wallet.GetPublicKeyArgs, originator string) (*wallet.GetPublicKeyResult, error) {
	require.Fail(m.T, "GetPublicKey mock not implemented")
	return nil, nil
}

func (m *MockWallet) RevealCounterpartyKeyLinkage(args wallet.RevealCounterpartyKeyLinkageArgs, originator string) (*wallet.RevealCounterpartyKeyLinkageResult, error) {
	require.Fail(m.T, "RevealCounterpartyKeyLinkage mock not implemented")
	return nil, nil
}

func (m *MockWallet) RevealSpecificKeyLinkage(args wallet.RevealSpecificKeyLinkageArgs, originator string) (*wallet.RevealSpecificKeyLinkageResult, error) {
	require.Fail(m.T, "RevealSpecificKeyLinkage mock not implemented")
	return nil, nil
}

func (m *MockWallet) Encrypt(args wallet.EncryptArgs, originator string) (*wallet.EncryptResult, error) {
	require.Fail(m.T, "Encrypt mock not implemented")
	return nil, nil
}

func (m *MockWallet) Decrypt(args wallet.DecryptArgs, originator string) (*wallet.DecryptResult, error) {
	require.Fail(m.T, "Decrypt mock not implemented")
	return nil, nil
}

func (m *MockWallet) CreateHmac(args wallet.CreateHmacArgs, originator string) (*wallet.CreateHmacResult, error) {
	require.Fail(m.T, "CreateHmac mock not implemented")
	return nil, nil
}

func (m *MockWallet) VerifyHmac(args wallet.VerifyHmacArgs, originator string) (*wallet.VerifyHmacResult, error) {
	require.Fail(m.T, "VerifyHmac mock not implemented")
	return nil, nil
}

func (m *MockWallet) CreateSignature(args wallet.CreateSignatureArgs, originator string) (*wallet.CreateSignatureResult, error) {
	require.Fail(m.T, "CreateSignature mock not implemented")
	return nil, nil
}

func (m *MockWallet) VerifySignature(args wallet.VerifySignatureArgs, originator string) (*wallet.VerifySignatureResult, error) {
	require.Fail(m.T, "VerifySignature mock not implemented")
	return nil, nil
}

func (m *MockWallet) AcquireCertificate(args wallet.AcquireCertificateArgs, originator string) (*wallet.Certificate, error) {
	require.Fail(m.T, "AcquireCertificate mock not implemented")
	return nil, nil
}

func (m *MockWallet) ListCertificates(args wallet.ListCertificatesArgs, originator string) (*wallet.ListCertificatesResult, error) {
	require.Fail(m.T, "ListCertificates mock not implemented")
	return nil, nil
}

func (m *MockWallet) ProveCertificate(args wallet.ProveCertificateArgs, originator string) (*wallet.ProveCertificateResult, error) {
	require.Fail(m.T, "ProveCertificate mock not implemented")
	return nil, nil
}

func (m *MockWallet) RelinquishCertificate(args wallet.RelinquishCertificateArgs, originator string) (*wallet.RelinquishCertificateResult, error) {
	require.Fail(m.T, "RelinquishCertificate mock not implemented")
	return nil, nil
}

func (m *MockWallet) DiscoverByIdentityKey(args wallet.DiscoverByIdentityKeyArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	require.Fail(m.T, "DiscoverByIdentityKey mock not implemented")
	return nil, nil
}

func (m *MockWallet) DiscoverByAttributes(args wallet.DiscoverByAttributesArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	require.Fail(m.T, "DiscoverByAttributes mock not implemented")
	return nil, nil
}

func (m *MockWallet) IsAuthenticated(args interface{}, originator string) (*wallet.AuthenticatedResult, error) {
	require.Fail(m.T, "IsAuthenticated mock not implemented")
	return nil, nil
}

func (m *MockWallet) WaitForAuthentication(args interface{}, originator string) (*wallet.AuthenticatedResult, error) {
	require.Fail(m.T, "WaitForAuthentication mock not implemented")
	return nil, nil
}

func (m *MockWallet) GetHeight(args interface{}, originator string) (*wallet.GetHeightResult, error) {
	require.Fail(m.T, "GetHeight mock not implemented")
	return nil, nil
}

func (m *MockWallet) GetHeaderForHeight(args wallet.GetHeaderArgs, originator string) (*wallet.GetHeaderResult, error) {
	require.Fail(m.T, "GetHeaderForHeight mock not implemented")
	return nil, nil
}

func (m *MockWallet) GetNetwork(args interface{}, originator string) (*wallet.GetNetworkResult, error) {
	require.Fail(m.T, "GetNetwork mock not implemented")
	return nil, nil
}

func (m *MockWallet) GetVersion(args interface{}, originator string) (*wallet.GetVersionResult, error) {
	require.Fail(m.T, "GetVersion mock not implemented")
	return nil, nil
}

func createTestWalletWire(wallet wallet.Interface) *WalletWireTransceiver {
	processor := NewWalletWireProcessor(wallet)
	return NewWalletWireTransceiver(processor)
}

func TestCreateAction(t *testing.T) {
	// Setup mock
	mockWallet := NewMockWallet(t)
	walletTransceiver := createTestWalletWire(mockWallet)

	t.Run("should create an action with valid inputs", func(t *testing.T) {
		// Expected arguments and return value
		mockWallet.ExpectedCreateActionArgs = &wallet.CreateActionArgs{
			Description: "Test action description",
			Outputs: []wallet.CreateActionOutput{{
				LockingScript:      "00",
				Satoshis:           1000,
				OutputDescription:  "Test output",
				Basket:             "test-basket",
				CustomInstructions: "Test instructions",
				Tags:               []string{"test-tag"},
			}},
			Labels: []string{"test-label"},
		}
		mockWallet.ExpectedOriginator = "test originator"

		mockWallet.CreateActionResultToReturn = &wallet.CreateActionResult{
			Txid: "deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806",
			Tx:   []byte{1, 2, 3, 4},
		}

		// Execute test
		result, err := walletTransceiver.CreateAction(*mockWallet.ExpectedCreateActionArgs, mockWallet.ExpectedOriginator)

		// Verify results
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, mockWallet.CreateActionResultToReturn.Txid, result.Txid)
		require.Equal(t, mockWallet.CreateActionResultToReturn.Tx, result.Tx)
		require.Nil(t, result.NoSendChange)
		require.Nil(t, result.SendWithResults)
		require.Nil(t, result.SignableTransaction)
	})

	t.Run("should create an action with minimal inputs (only description)", func(t *testing.T) {
		// Expected arguments and return value
		mockWallet.ExpectedCreateActionArgs = &wallet.CreateActionArgs{
			Description: "Minimal action description",
		}
		mockWallet.ExpectedOriginator = ""
		mockWallet.CreateActionResultToReturn = &wallet.CreateActionResult{
			Txid: "deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806",
		}

		// Execute test
		result, err := walletTransceiver.CreateAction(*mockWallet.ExpectedCreateActionArgs, mockWallet.ExpectedOriginator)

		// Verify results
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, mockWallet.CreateActionResultToReturn.Txid, result.Txid)
		require.Nil(t, result.Tx)
		require.Nil(t, result.NoSendChange)
		require.Nil(t, result.SendWithResults)
		require.Nil(t, result.SignableTransaction)
	})
}

func TestTsCompatibility(t *testing.T) {
	const createActionFrame = "0100175465737420616374696f6e206465736372697074696f6effffffffffffffffffffffffffffffffffff010100fde8031754657374206f7574707574206465736372697074696f6effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00"
	frame, err := hex.DecodeString(createActionFrame)
	require.Nil(t, err)
	request, err := serializer.ReadRequestFrame(frame)
	require.Nil(t, err)
	require.Equal(t, uint8(CallCreateAction), request.Call)
	createActionArgs, err := serializer.DeserializeCreateActionArgs(request.Params)
	require.Nil(t, err)
	require.Equal(t, wallet.CreateActionArgs{
		Description: "Test action description",
		Outputs: []wallet.CreateActionOutput{{
			LockingScript:     "00",
			Satoshis:          1000,
			OutputDescription: "Test output description",
		}},
	}, *createActionArgs)
}
