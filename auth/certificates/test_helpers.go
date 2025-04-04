package certificates

import (
	"errors"
	"math/rand"

	"github.com/bsv-blockchain/go-sdk/overlay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// TestWalletHelper provides utility functions for creating and managing test wallets
type TestWalletHelper struct{}

// CreateTestWallet creates a wallet for testing with a randomly generated private key
func (h *TestWalletHelper) CreateTestWallet() (*wallet.Wallet, error) {
	// Generate a random private key
	// Create a random 32-byte private key
	privateKeyBytes := make([]byte, 32)
	if _, err := rand.Read(privateKeyBytes); err != nil {
		return nil, err
	}

	// Create EC private key from the random bytes
	privateKey, _ := ec.PrivateKeyFromBytes(privateKeyBytes)

	// Create a wallet with the private key
	walletInstance := wallet.NewWallet(privateKey)
	return walletInstance, nil
}

// CreateTestWalletPair creates a pair of wallets for testing, typically for certifier and subject
func (h *TestWalletHelper) CreateTestWalletPair() (*wallet.Wallet, *wallet.Wallet, error) {
	certifierWallet, err := h.CreateTestWallet()
	if err != nil {
		return nil, nil, err
	}

	subjectWallet, err := h.CreateTestWallet()
	if err != nil {
		return nil, nil, err
	}

	return certifierWallet, subjectWallet, nil
}

// CreateThreeTestWallets creates three wallets for testing (certifier, subject, verifier)
func (h *TestWalletHelper) CreateThreeTestWallets() (*wallet.Wallet, *wallet.Wallet, *wallet.Wallet, error) {
	certifierWallet, subjectWallet, err := h.CreateTestWalletPair()
	if err != nil {
		return nil, nil, nil, err
	}

	verifierWallet, err := h.CreateTestWallet()
	if err != nil {
		return nil, nil, nil, err
	}

	return certifierWallet, subjectWallet, verifierWallet, nil
}

// CreateTestFieldsAndPairs creates certificate fields and crypto wallet pairs for testing
func (h *TestWalletHelper) CreateTestFieldsAndPairs() (map[string]string, *wallet.Wallet, *wallet.Wallet, *wallet.Wallet, error) {
	// Create some test certificate fields
	fields := map[string]string{
		"name":       "John Doe",
		"age":        "25",
		"isVerified": "true",
	}

	// Create test wallets
	certifierWallet, subjectWallet, verifierWallet, err := h.CreateThreeTestWallets()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return fields, certifierWallet, subjectWallet, verifierWallet, nil
}

// CreateCounterpartyFromWallet creates a Counterparty from a wallet
func (h *TestWalletHelper) CreateCounterpartyFromWallet(walletInstance *wallet.Wallet) (*wallet.Counterparty, error) {
	if walletInstance == nil {
		return nil, errors.New("wallet cannot be nil")
	}

	// Get the identity public key from the wallet
	pubKeyResult, err := walletInstance.GetPublicKey(&wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, "")

	if err != nil {
		return nil, err
	}

	// Create a counterparty with the public key
	counterparty := &wallet.Counterparty{
		Type:         wallet.CounterpartyTypeOther,
		Counterparty: pubKeyResult.PublicKey,
	}

	return counterparty, nil
}

// GenerateRandomRevocationOutpoint generates a random revocation outpoint for testing
func (h *TestWalletHelper) GenerateRandomRevocationOutpoint() *overlay.Outpoint {
	// Create a simple revocation outpoint
	// In a real implementation, this would be linked to a transaction
	return &overlay.Outpoint{}
}

// GetRevocationOutpointFunc returns a function for generating revocation outpoints
func (h *TestWalletHelper) GetRevocationOutpointFunc() func(string) (*overlay.Outpoint, error) {
	return func(serialNumber string) (*overlay.Outpoint, error) {
		return h.GenerateRandomRevocationOutpoint(), nil
	}
}
