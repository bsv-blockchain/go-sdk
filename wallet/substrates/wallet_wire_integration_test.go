package substrates

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"testing"
)

type MockWallet struct {
}

func (m *MockWallet) CreateAction(args wallet.CreateActionArgs) (*wallet.CreateActionResult, error) {
	return &wallet.CreateActionResult{
		Txid: "deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806",
		Tx:   []byte{1, 2, 3, 4},
	}, nil
}

func createTestWalletWire(wallet wallet.Interface) *WalletWireTransceiver {
	processor := NewWalletWireProcessor(wallet)
	return NewWalletWireTransceiver(processor)
}

func TestCreateAction(t *testing.T) {
	// Setup mock
	mockWallet := new(MockWallet)
	walletTransceiver := createTestWalletWire(mockWallet)

	// Expected arguments and return value
	expectedArgs := wallet.CreateActionArgs{
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

	expectedResult := &wallet.CreateActionResult{
		Txid: "deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806",
		Tx:   []byte{1, 2, 3, 4},
	}

	// Execute test
	result, err := walletTransceiver.CreateAction(expectedArgs)

	// Verify results
	assert.NoError(t, err)
	assert.Equal(t, expectedResult, result)
	assert.Equal(t, expectedResult.Txid, result.Txid)
	assert.Equal(t, expectedResult.Tx, result.Tx)
}
