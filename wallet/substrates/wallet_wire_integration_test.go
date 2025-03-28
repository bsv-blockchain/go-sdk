package substrates

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
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

func createTestWalletWire(wallet wallet.Interface) *WalletWireTransceiver {
	processor := NewWalletWireProcessor(wallet)
	return NewWalletWireTransceiver(processor)
}

func TestCreateAction(t *testing.T) {
	// Setup mock
	mockWallet := NewMockWallet(t)
	walletTransceiver := createTestWalletWire(mockWallet)

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
}
