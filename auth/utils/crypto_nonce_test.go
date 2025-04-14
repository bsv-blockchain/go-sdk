package utils

import (
	"errors"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
)

// CompletedProtoWallet embeds the ProtoWallet and implements wallet.Interface
// Similar to the TypeScript implementation that extends ProtoWallet and implements WalletInterface
type CompletedProtoWallet struct {
	*wallet.ProtoWallet // Embed ProtoWallet (like extends in TypeScript)
	keyDeriver          *wallet.KeyDeriver
}

// NewCompletedProtoWallet creates a new CompletedProtoWallet from a private key
func NewCompletedProtoWallet(privateKey *ec.PrivateKey) (*CompletedProtoWallet, error) {
	protoWallet, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{Type: wallet.ProtoWalletArgsTypePrivateKey, PrivateKey: privateKey})
	if err != nil {
		return nil, err
	}

	keyDeriver := wallet.NewKeyDeriver(privateKey)
	return &CompletedProtoWallet{
		ProtoWallet: protoWallet, // Directly embed the ProtoWallet
		keyDeriver:  keyDeriver,
	}, nil
}

// CreateAction creates a new transaction (not needed for certificates)
func (c *CompletedProtoWallet) CreateAction(args wallet.CreateActionArgs, originator string) (*wallet.CreateActionResult, error) {
	return nil, errors.New("CreateAction not implemented in CompletedProtoWallet")
}

// ListCertificates lists certificates (not needed for our tests)
func (c *CompletedProtoWallet) ListCertificates(args wallet.ListCertificatesArgs) (*wallet.ListCertificatesResult, error) {
	return nil, errors.New("ListCertificates not implemented in CompletedProtoWallet")
}

// ProveCertificate creates verifiable certificates (not needed for our tests)
func (c *CompletedProtoWallet) ProveCertificate(args wallet.ProveCertificateArgs) (*wallet.ProveCertificateResult, error) {
	return nil, errors.New("ProveCertificate not implemented in CompletedProtoWallet")
}

// IsAuthenticated checks if the wallet is authenticated
func (c *CompletedProtoWallet) IsAuthenticated(args any) (bool, error) {
	return true, nil // Always authenticated for testing
}

// GetHeight gets the current block height
func (c *CompletedProtoWallet) GetHeight(args any) (uint32, error) {
	return 0, nil // Return 0 height for testing
}

// GetNetwork gets the current network
func (c *CompletedProtoWallet) GetNetwork(args any) (string, error) {
	return "test", nil // Always test network for testing
}

// GetVersion gets the wallet version
func (c *CompletedProtoWallet) GetVersion(args any) (string, error) {
	return "test", nil // Always test version for testing
}

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
