package utils

import (
	"context"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/v2/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/v2/wallet"
	"github.com/stretchr/testify/require"
)

func TestCreateNonce(t *testing.T) {
	// Create a wallet with a random private key
	privateKey, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}
	completedWallet, err := NewCompletedProtoWallet(privateKey)
	if err != nil {
		t.Fatalf("Failed to create completed wallet: %v", err)
	}

	ctx := context.Background()

	// Test creating a nonce
	nonce, err := CreateNonce(ctx, completedWallet, wallet.Counterparty{
		Type: wallet.CounterpartyTypeSelf,
	})
	require.NoError(t, err, "Should not error when creating nonce")
	require.NotEmpty(t, nonce, "Nonce should not be empty")

	// Create another nonce to verify they're different
	nonce2, err := CreateNonce(ctx, completedWallet, wallet.Counterparty{
		Type: wallet.CounterpartyTypeSelf,
	})
	require.NoError(t, err, "Should not error when creating second nonce")
	require.NotEmpty(t, nonce2, "Second nonce should not be empty")
	require.NotEqual(t, nonce, nonce2, "Two nonces should be different")
}

func TestVerifyNonce(t *testing.T) {
	// Create a wallet with a random private key
	privateKey, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to create private key: %v", err)
	}
	completedWallet, err := NewCompletedProtoWallet(privateKey)
	if err != nil {
		t.Fatalf("Failed to create completed wallet: %v", err)
	}

	// Create a valid nonce
	counterparty := wallet.Counterparty{
		Type: wallet.CounterpartyTypeSelf,
	}

	nonce, err := CreateNonce(t.Context(), completedWallet, counterparty)
	require.NoError(t, err, "Failed to create nonce")

	// Verify the valid nonce
	valid, err := VerifyNonce(t.Context(), nonce, completedWallet, counterparty)
	require.NoError(t, err, "Should not error when verifying a valid nonce")
	require.True(t, valid, "Valid nonce should verify successfully")

	// Test invalid nonce (wrong format)
	valid, err = VerifyNonce(t.Context(), "invalidnonce", completedWallet, counterparty)
	require.Error(t, err, "Should error with invalid nonce format")
	require.False(t, valid, "Invalid nonce should not verify")

	// Test with different counterparty type (should fail)
	valid, err = VerifyNonce(t.Context(), nonce, completedWallet, wallet.Counterparty{
		Type: wallet.CounterpartyTypeAnyone,
	})
	require.NoError(t, err, "Should not error with valid nonce format but invalid counterparty")
	require.False(t, valid, "Nonce with mismatched counterparty should not verify")
}
