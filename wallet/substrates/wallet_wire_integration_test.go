package substrates

import (
	"encoding/hex"
	"testing"

	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/serializer"
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
	ctx := t.Context()

	t.Run("should create an action with valid inputs", func(t *testing.T) {
		// Expected arguments and return value
		mock.ExpectedCreateActionArgs = &wallet.CreateActionArgs{
			Description: "Test action description",
			Outputs: []wallet.CreateActionOutput{{
				LockingScript:      "76a9143cf53c49c322d9d811728182939aee2dca087f9888ac",
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
		result, err := walletTransceiver.CreateAction(ctx, *mock.ExpectedCreateActionArgs, mock.ExpectedOriginator)

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
		result, err := walletTransceiver.CreateAction(ctx, *mock.ExpectedCreateActionArgs, mock.ExpectedOriginator)

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
