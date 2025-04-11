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
	protoWallet, err := wallet.NewProtoWallet(privateKey)
	if err != nil {
		return nil, err
	}

	keyDeriver := wallet.NewKeyDeriver(privateKey)
	return &CompletedProtoWallet{
		ProtoWallet: protoWallet, // Directly embed the ProtoWallet
		keyDeriver:  keyDeriver,
	}, nil
}

// GetProtoWallet returns the embedded *wallet.ProtoWallet
// This allows the CompletedProtoWallet to be used where a *wallet.ProtoWallet is expected
func (c *CompletedProtoWallet) GetProtoWallet() *wallet.ProtoWallet {
	return c.ProtoWallet
}

// GetPublicKey returns the public key for specific purposes, implementing the wallet.Interface
// This overrides the ProtoWallet's GetPublicKey method to match the wallet.Interface signature
func (c *CompletedProtoWallet) GetPublicKey(args *wallet.GetPublicKeyArgs, originator string) (*wallet.GetPublicKeyResult, error) {
	pubKey, err := c.ProtoWallet.GetPublicKey(args)
	if err != nil {
		return nil, err
	}
	return &wallet.GetPublicKeyResult{
		PublicKey: pubKey,
	}, nil
}

// CreateSignature creates a signature for the provided data
func (c *CompletedProtoWallet) CreateSignature(args *wallet.CreateSignatureArgs, originator string) (*wallet.CreateSignatureResult, error) {
	return c.ProtoWallet.CreateSignature(args, originator)
}

// VerifySignature verifies a signature for the provided data
func (c *CompletedProtoWallet) VerifySignature(args *wallet.VerifySignatureArgs) (*wallet.VerifySignatureResult, error) {
	return c.ProtoWallet.VerifySignature(args)
}

// Encrypt encrypts data using the provided protocol ID and key ID
func (c *CompletedProtoWallet) Encrypt(args *wallet.EncryptArgs) (*wallet.EncryptResult, error) {
	ciphertext, err := c.ProtoWallet.Encrypt(args)
	if err != nil {
		return nil, err
	}
	return &wallet.EncryptResult{
		Ciphertext: ciphertext,
	}, nil
}

// Decrypt decrypts data using the provided protocol ID and key ID
func (c *CompletedProtoWallet) Decrypt(args *wallet.DecryptArgs) (*wallet.DecryptResult, error) {
	plaintext, err := c.ProtoWallet.Decrypt(args)
	if err != nil {
		return nil, err
	}
	return &wallet.DecryptResult{
		Plaintext: plaintext,
	}, nil
}

// CreateHmac creates an HMAC for the provided data
func (c *CompletedProtoWallet) CreateHmac(args wallet.CreateHmacArgs) (*wallet.CreateHmacResult, error) {
	return c.ProtoWallet.CreateHmac(args)
}

// VerifyHmac verifies an HMAC for the provided data
func (c *CompletedProtoWallet) VerifyHmac(args wallet.VerifyHmacArgs) (*wallet.VerifyHmacResult, error) {
	return c.ProtoWallet.VerifyHmac(args)
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
