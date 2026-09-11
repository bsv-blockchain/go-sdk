package registry

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/overlay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const revokeTestTxID = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

// unsupportedDefinition is a DefinitionData whose concrete type is not one of
// the three known registry types, forcing buildPushDropFields to fail.
type unsupportedDefinition struct{}

func (unsupportedDefinition) GetDefinitionType() DefinitionType { return DefinitionType("mystery") }
func (unsupportedDefinition) GetRegistryOperator() string       { return "" }

func TestRegisterDefinitionBuildFieldsError(t *testing.T) {
	mw := NewMockRegistry(t)
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: makeTestPubKey(t)}

	client := NewRegistryClient(mw, "originator")
	client.SetNetwork(overlay.NetworkLocal)

	_, err := client.RegisterDefinition(context.Background(), unsupportedDefinition{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to build push drop fields")
}

func TestRegisterDefinitionLockError(t *testing.T) {
	mw := NewMockRegistry(t)
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: makeTestPubKey(t)}
	mw.CreateSignatureError = errors.New("cannot sign locking script")

	client := NewRegistryClient(mw, "originator")
	client.SetNetwork(overlay.NetworkLocal)

	_, err := client.RegisterDefinition(context.Background(), &BasketDefinitionData{
		DefinitionType: DefinitionTypeBasket, BasketID: "b1", Name: "N",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create locking script")
}

func TestRegisterDefinitionCreateActionError(t *testing.T) {
	mw := &walletWithCreateActionError{MockRegistry: NewMockRegistry(t), err: errors.New("wallet busy")}
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: makeTestPubKey(t)}
	mw.CreateSignatureResult = &wallet.CreateSignatureResult{
		Signature: &ec.Signature{R: big.NewInt(1), S: big.NewInt(1)},
	}

	client := NewRegistryClient(mw, "originator")
	client.SetNetwork(overlay.NetworkLocal)

	_, err := client.RegisterDefinition(context.Background(), &BasketDefinitionData{
		DefinitionType: DefinitionTypeBasket, BasketID: "b1", Name: "N",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create transaction")
}

func TestRegisterDefinitionInvalidCreatedBEEF(t *testing.T) {
	mw := NewMockRegistry(t)
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: makeTestPubKey(t)}
	mw.CreateSignatureResult = &wallet.CreateSignatureResult{
		Signature: &ec.Signature{R: big.NewInt(1), S: big.NewInt(1)},
	}
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{Tx: []byte("not-valid-beef")}

	client := NewRegistryClient(mw, "originator")
	client.SetNetwork(overlay.NetworkLocal)
	client.SetBroadcasterFactory(successBroadcasterFactory("aabbcc"))

	_, err := client.RegisterDefinition(context.Background(), &BasketDefinitionData{
		DefinitionType: DefinitionTypeBasket, BasketID: "b1", Name: "N",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create transaction from BEEF")
}

func TestRevokeOwnRegistryEntryUnlockerSignError(t *testing.T) {
	key := makeTestPubKey(t)
	beef := decodeValidBeef(t)
	mw := NewMockRegistry(t)
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: key}
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{
		SignableTransaction: &wallet.SignableTransaction{Tx: beef, Reference: []byte("ref")},
	}
	mw.CreateSignatureError = errors.New("cannot sign spend")

	record := &RegistryRecord{
		DefinitionData: &BasketDefinitionData{
			DefinitionType:   DefinitionTypeBasket,
			RegistryOperator: key.ToDERHex(),
		},
		TokenData: TokenData{
			TxID:          revokeTestTxID,
			LockingScript: testSomeScript,
			BEEF:          beef,
		},
	}

	client := NewRegistryClient(mw, "originator")
	client.SetNetwork(overlay.NetworkLocal)
	_, err := client.RevokeOwnRegistryEntry(context.Background(), record)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to sign transaction")
}

func TestRevokeOwnRegistryEntryDefaultBroadcasterFallback(t *testing.T) {
	// With a nil broadcaster factory, RevokeOwnRegistryEntry falls back to the
	// default topic.NewBroadcaster. Outbound HTTP is disabled so the broadcast
	// itself yields a failure rather than a transport error.
	tu.WithUnreachableTransport(t)

	key := makeTestPubKey(t)
	beef := decodeValidBeef(t)
	txID := mockTxid(t)
	mw := NewMockRegistry(t)
	mw.GetPublicKeyResult = &wallet.GetPublicKeyResult{PublicKey: key}
	mw.CreateActionResultToReturn = &wallet.CreateActionResult{
		SignableTransaction: &wallet.SignableTransaction{Tx: beef, Reference: []byte("ref")},
	}
	mw.CreateSignatureResult = &wallet.CreateSignatureResult{
		Signature: &ec.Signature{R: big.NewInt(1), S: big.NewInt(1)},
	}
	mw.SignActionResultToReturn = &wallet.SignActionResult{Tx: beef, Txid: *txID}

	record := &RegistryRecord{
		DefinitionData: &BasketDefinitionData{
			DefinitionType:   DefinitionTypeBasket,
			RegistryOperator: key.ToDERHex(),
		},
		TokenData: TokenData{
			TxID:          revokeTestTxID,
			LockingScript: testSomeScript,
			BEEF:          beef,
		},
	}

	client := NewRegistryClient(mw, "originator")
	client.SetNetwork(overlay.NetworkLocal)
	client.SetBroadcasterFactory(nil) // force the default-broadcaster fallback

	result, err := client.RevokeOwnRegistryEntry(context.Background(), record)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Nil(t, result.Success)
	require.NotNil(t, result.Failure)
}
