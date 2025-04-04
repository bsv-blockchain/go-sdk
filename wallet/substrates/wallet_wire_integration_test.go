package substrates

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func createTestWalletWire(wallet wallet.Interface) *WalletWireTransceiver {
	processor := NewWalletWireProcessor(wallet)
	return NewWalletWireTransceiver(processor)
}

func TestCreateAction(t *testing.T) {
	// Setup mock
	mock := wallet.NewMockWallet(t)
	walletTransceiver := createTestWalletWire(mock)

	t.Run("should create an action with valid inputs", func(t *testing.T) {
		// Expected arguments and return value
		mock.ExpectedCreateActionArgs = &wallet.CreateActionArgs{
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
		mock.ExpectedOriginator = "test originator"

		mock.CreateActionResultToReturn = &wallet.CreateActionResult{
			Txid: "deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806",
			Tx:   []byte{1, 2, 3, 4},
		}

		// Execute test
		result, err := walletTransceiver.CreateAction(*mock.ExpectedCreateActionArgs, mock.ExpectedOriginator)

		// Verify results
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, mock.CreateActionResultToReturn.Txid, result.Txid)
		require.Equal(t, mock.CreateActionResultToReturn.Tx, result.Tx)
		require.Nil(t, result.NoSendChange)
		require.Nil(t, result.SendWithResults)
		require.Nil(t, result.SignableTransaction)
	})

	t.Run("should create an action with minimal inputs (only description)", func(t *testing.T) {
		// Expected arguments and return value
		mock.ExpectedCreateActionArgs = &wallet.CreateActionArgs{
			Description: "Minimal action description",
		}
		mock.ExpectedOriginator = ""
		mock.CreateActionResultToReturn = &wallet.CreateActionResult{
			Txid: "deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806",
		}

		// Execute test
		result, err := walletTransceiver.CreateAction(*mock.ExpectedCreateActionArgs, mock.ExpectedOriginator)

		// Verify results
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, mock.CreateActionResultToReturn.Txid, result.Txid)
		require.Nil(t, result.Tx)
		require.Nil(t, result.NoSendChange)
		require.Nil(t, result.SendWithResults)
		require.Nil(t, result.SignableTransaction)
	})
}
