package utils

import (
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
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

	// Test creating a nonce
	nonce, err := CreateNonce(completedWallet, wallet.CounterpartyTypeSelf)
	assert.NoError(t, err, "Should not error when creating nonce")
	assert.NotEmpty(t, nonce, "Nonce should not be empty")

	// Create another nonce to verify they're different
	nonce2, err := CreateNonce(completedWallet, wallet.CounterpartyTypeSelf)
	assert.NoError(t, err, "Should not error when creating second nonce")
	assert.NotEmpty(t, nonce2, "Second nonce should not be empty")
	assert.NotEqual(t, nonce, nonce2, "Two nonces should be different")
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
	counterpartyType := wallet.CounterpartyTypeSelf
	nonce, err := CreateNonce(completedWallet, counterpartyType)
	assert.NoError(t, err, "Failed to create nonce")

	// Verify the valid nonce
	valid, err := VerifyNonce(nonce, completedWallet, counterpartyType)
	assert.NoError(t, err, "Should not error when verifying a valid nonce")
	assert.True(t, valid, "Valid nonce should verify successfully")

	// Test invalid nonce (wrong format)
	valid, err = VerifyNonce("invalidnonce", completedWallet, counterpartyType)
	assert.Error(t, err, "Should error with invalid nonce format")
	assert.False(t, valid, "Invalid nonce should not verify")

	// Test with different counterparty type (should fail)
	valid, err = VerifyNonce(nonce, completedWallet, wallet.CounterpartyTypeAnyone)
	assert.NoError(t, err, "Should not error with valid nonce format but invalid counterparty")
	assert.False(t, valid, "Nonce with mismatched counterparty should not verify")
}
