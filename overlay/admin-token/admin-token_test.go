package admintoken_test

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	admintoken "github.com/bsv-blockchain/go-sdk/overlay/admin-token"
	"github.com/bsv-blockchain/go-sdk/overlay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// Helper function to create a test wallet with a fixed private key
func createTestWallet(t *testing.T) *wallet.CompletedProtoWallet {
	// Using private key = 1 to match TypeScript test
	privKeyBytes := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	privKey, _ := ec.PrivateKeyFromBytes(privKeyBytes)
	testWallet, err := wallet.NewCompletedProtoWallet(privKey)
	require.NoError(t, err)
	return testWallet
}

func TestOverlayAdminToken_LockAndDecode(t *testing.T) {
	t.Run("Creates a script that can be decoded", func(t *testing.T) {
		testWallet := createTestWallet(t)
		template := admintoken.NewOverlayAdminToken(testWallet, "test-originator")

		ctx := context.Background()
		protocol := overlay.ProtocolSHIP
		domain := "test.com"
		topicOrService := "tm_tests"

		lockingScript, err := template.Lock(ctx, protocol, domain, topicOrService)
		require.NoError(t, err)
		assert.NotNil(t, lockingScript)

		decoded := admintoken.Decode(lockingScript)
		require.NotNil(t, decoded)
		assert.Equal(t, protocol, decoded.Protocol)
		assert.Equal(t, domain, decoded.Domain)
		assert.Equal(t, topicOrService, decoded.TopicOrService)
		
		// Get the identity key to verify it matches
		identityKey, err := testWallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
			IdentityKey: true,
		}, "test-originator")
		require.NoError(t, err)
		assert.Equal(t, hex.EncodeToString(identityKey.PublicKey.Compressed()), decoded.IdentityKey)
	})

	t.Run("Will not decode with invalid field count or protocol", func(t *testing.T) {
		testWallet := createTestWallet(t)
		pushDrop := &pushdrop.PushDrop{
			Wallet:     testWallet,
			Originator: "test-originator",
		}

		ctx := context.Background()
		protocolID := wallet.Protocol{SecurityLevel: 2, Protocol: "tests"}
		keyID := "1"
		counterparty := wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}

		// Create script with bad field count (3 fields instead of 4)
		scriptBadFieldCount, err := pushDrop.Lock(
			ctx,
			[][]byte{{1}, {2}, {3}},
			protocolID,
			keyID,
			counterparty,
			false, // forSelf
			true,  // includeSignature
			pushdrop.LockBefore,
		)
		require.NoError(t, err)

		// Create script with bad protocol (first field is [1] instead of "SHIP" or "SLAP")
		scriptBadProtocol, err := pushDrop.Lock(
			ctx,
			[][]byte{{1}, {2}, {3}, {4}},
			protocolID,
			keyID,
			counterparty,
			false, // forSelf
			true,  // includeSignature
			pushdrop.LockBefore,
		)
		require.NoError(t, err)

		// Both should return nil when decoding fails
		decodedBadFieldCount := admintoken.Decode(scriptBadFieldCount)
		assert.Nil(t, decodedBadFieldCount)

		decodedBadProtocol := admintoken.Decode(scriptBadProtocol)
		assert.Nil(t, decodedBadProtocol)
	})
}

func TestOverlayAdminToken_Unlock(t *testing.T) {
	t.Run("creates a correct unlocking script", func(t *testing.T) {
		testWallet := createTestWallet(t)
		template := admintoken.NewOverlayAdminToken(testWallet, "test-originator")

		ctx := context.Background()
		protocol := overlay.ProtocolSLAP
		domain := "test.com"
		topicOrService := "ls_tests"

		// Create locking script
		lockingScript, err := template.Lock(ctx, protocol, domain, topicOrService)
		require.NoError(t, err)
		assert.NotNil(t, lockingScript)

		// Create unlocking template
		unlocker := template.Unlock(ctx, protocol)
		require.NotNil(t, unlocker)

		// Verify estimated length
		assert.Equal(t, uint32(73), unlocker.EstimateLength())

		// Create source transaction with the locking script
		satoshis := uint64(1)
		sourceTx := transaction.NewTransaction()
		sourceTx.AddOutput(&transaction.TransactionOutput{
			Satoshis:      satoshis,
			LockingScript: lockingScript,
		})

		// Create spending transaction
		spendTx := transaction.NewTransaction()
		spendTx.AddInputFromTx(sourceTx, 0, nil)

		// Sign the input
		unlockingScript, err := unlocker.Sign(spendTx, 0)
		require.NoError(t, err)
		require.NotNil(t, unlockingScript)

		// Set the unlocking script
		spendTx.Inputs[0].UnlockingScript = unlockingScript

		// Validate the script execution
		err = interpreter.NewEngine().Execute(
			interpreter.WithTx(spendTx, 0, &transaction.TransactionOutput{
				Satoshis:      satoshis,
				LockingScript: lockingScript,
			}),
			interpreter.WithForkID(),
			interpreter.WithAfterGenesis(),
		)
		assert.NoError(t, err)
	})
}



