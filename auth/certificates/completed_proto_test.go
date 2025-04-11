package certificates

import (
	"errors"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
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
