package substrates

import (
	"context"
	"encoding/hex"
	"testing"

	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
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
	mock := wallet.NewTestWalletForRandomKey(t)
	walletTransceiver := createTestWalletWire(mock)
	ctx := t.Context()
	txID := tu.GetByte32FromHexString(t, "deadbeef20248806deadbeef20248806deadbeef20248806deadbeef20248806")

	t.Run("should create an action with valid inputs", func(t *testing.T) {
		// Expected arguments and return value
		lockScript, err := hex.DecodeString("76a9143cf53c49c322d9d811728182939aee2dca087f9888ac")
		require.NoError(t, err, "decoding locking script should not error")

		var expectedCreateActionArgs = wallet.CreateActionArgs{
			Description: "Test action description",
			Outputs: []wallet.CreateActionOutput{{
				LockingScript:      lockScript,
				Satoshis:           1000,
				OutputDescription:  "Test output",
				Basket:             "test-basket",
				CustomInstructions: "Test instructions",
				Tags:               []string{"test-tag"},
			}},
			Labels: []string{"test-label"},
		}

		const originator = "test originator"

		var expectedResult = &wallet.CreateActionResult{
			Txid: txID,
			Tx:   []byte{1, 2, 3, 4},
		}

		mock.OnCreateAction().
			Expect(func(ctx context.Context, args wallet.CreateActionArgs, originator string) {
				require.Equal(t, expectedCreateActionArgs.Description, args.Description)
				require.Equal(t, expectedCreateActionArgs.Outputs, args.Outputs)
				require.Equal(t, expectedCreateActionArgs.Labels, args.Labels)
			}).
			ExpectOriginator(originator).
			ReturnSuccess(expectedResult)

		// Execute test
		result, err := walletTransceiver.CreateAction(ctx, expectedCreateActionArgs, originator)

		// Verify results
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, expectedResult.Txid, result.Txid)
		require.Equal(t, expectedResult.Tx, result.Tx)
		require.Nil(t, result.NoSendChange)
		require.Nil(t, result.SendWithResults)
		require.Nil(t, result.SignableTransaction)
	})

	t.Run("should create an action with minimal inputs (only description)", func(t *testing.T) {
		// Expected arguments and return value
		var expectedCreateActionArgs = wallet.CreateActionArgs{
			Description: "Minimal action description",
		}

		var expectedResult = &wallet.CreateActionResult{
			Txid: txID,
		}

		mock.OnCreateAction().
			Expect(func(ctx context.Context, args wallet.CreateActionArgs, originator string) {
				require.Equal(t, expectedCreateActionArgs.Description, args.Description)
			}).
			ReturnSuccess(expectedResult)

		// Execute test
		result, err := walletTransceiver.CreateAction(ctx, expectedCreateActionArgs, "")

		// Verify results
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, expectedResult.Txid, result.Txid)
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
			LockingScript:     []byte{0x00},
			Satoshis:          1000,
			OutputDescription: "Test output description",
		}},
	}, *createActionArgs)
}
