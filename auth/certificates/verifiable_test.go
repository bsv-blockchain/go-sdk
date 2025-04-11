package certificates

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// TestWalletInterface provides a mock implementation for testing
// It can delegate to either a ProtoWallet or a regular Wallet
type TestWalletInterface struct {
	Wallet      wallet.Interface
	ProtoWallet *wallet.ProtoWallet
}

// GetPublicKey delegates to the appropriate wallet implementation
func (t *TestWalletInterface) GetPublicKey(args *wallet.GetPublicKeyArgs, originator string) (*wallet.GetPublicKeyResult, error) {
	if t.ProtoWallet != nil {
		pubKey, err := t.ProtoWallet.GetPublicKey(args)
		if err != nil {
			return nil, err
		}
		return &wallet.GetPublicKeyResult{
			PublicKey: pubKey,
		}, nil
	}
	return t.Wallet.GetPublicKey(args, originator)
}

// CreateAction delegates to the appropriate wallet implementation
func (t *TestWalletInterface) CreateAction(args wallet.CreateActionArgs, originator string) (*wallet.CreateActionResult, error) {
	if t.ProtoWallet != nil {
		// ProtoWallet doesn't implement this method
		return nil, nil
	}
	return t.Wallet.CreateAction(args, originator)
}

// CreateSignature delegates to the appropriate wallet implementation
func (t *TestWalletInterface) CreateSignature(args *wallet.CreateSignatureArgs, originator string) (*wallet.CreateSignatureResult, error) {
	if t.ProtoWallet != nil {
		return t.ProtoWallet.CreateSignature(args, originator)
	}
	return t.Wallet.CreateSignature(args, originator)
}

// VerifySignature delegates to the appropriate wallet implementation
func (t *TestWalletInterface) VerifySignature(args *wallet.VerifySignatureArgs) (*wallet.VerifySignatureResult, error) {
	if t.ProtoWallet != nil {
		return t.ProtoWallet.VerifySignature(args)
	}
	return t.Wallet.VerifySignature(args)
}

// Encrypt delegates to the appropriate wallet implementation
func (t *TestWalletInterface) Encrypt(args *wallet.EncryptArgs) (*wallet.EncryptResult, error) {
	if t.ProtoWallet != nil {
		ciphertext, err := t.ProtoWallet.Encrypt(args)
		if err != nil {
			return nil, err
		}
		return &wallet.EncryptResult{Ciphertext: ciphertext}, nil
	}
	return t.Wallet.Encrypt(args)
}

// Decrypt delegates to the appropriate wallet implementation
func (t *TestWalletInterface) Decrypt(args *wallet.DecryptArgs) (*wallet.DecryptResult, error) {
	if t.ProtoWallet != nil {
		plaintext, err := t.ProtoWallet.Decrypt(args)
		if err != nil {
			return nil, err
		}
		return &wallet.DecryptResult{Plaintext: plaintext}, nil
	}
	return t.Wallet.Decrypt(args)
}

// CreateHmac delegates to the appropriate wallet implementation
func (t *TestWalletInterface) CreateHmac(args wallet.CreateHmacArgs) (*wallet.CreateHmacResult, error) {
	if t.ProtoWallet != nil {
		return t.ProtoWallet.CreateHmac(args)
	}
	return t.Wallet.CreateHmac(args)
}

// VerifyHmac delegates to the appropriate wallet implementation
func (t *TestWalletInterface) VerifyHmac(args wallet.VerifyHmacArgs) (*wallet.VerifyHmacResult, error) {
	if t.ProtoWallet != nil {
		return t.ProtoWallet.VerifyHmac(args)
	}
	return t.Wallet.VerifyHmac(args)
}

// ListCertificates delegates to the appropriate wallet implementation
func (t *TestWalletInterface) ListCertificates(args wallet.ListCertificatesArgs) (*wallet.ListCertificatesResult, error) {
	if t.ProtoWallet != nil {
		// ProtoWallet doesn't implement this method
		return nil, nil
	}
	return t.Wallet.ListCertificates(args)
}

// ProveCertificate delegates to the appropriate wallet implementation
func (t *TestWalletInterface) ProveCertificate(args wallet.ProveCertificateArgs) (*wallet.ProveCertificateResult, error) {
	if t.ProtoWallet != nil {
		// ProtoWallet doesn't implement this method
		return nil, nil
	}
	return t.Wallet.ProveCertificate(args)
}

// GetHeight delegates to the appropriate wallet implementation
func (t *TestWalletInterface) GetHeight(args interface{}) (uint32, error) {
	if t.ProtoWallet != nil {
		// ProtoWallet doesn't implement this method
		return 0, nil
	}
	return t.Wallet.GetHeight(args)
}

// IsAuthenticated delegates to the appropriate wallet implementation
func (t *TestWalletInterface) IsAuthenticated(args interface{}) (bool, error) {
	if t.ProtoWallet != nil {
		// ProtoWallet doesn't implement this method
		return true, nil
	}
	return t.Wallet.IsAuthenticated(args)
}

// GetNetwork delegates to the appropriate wallet implementation
func (t *TestWalletInterface) GetNetwork(args interface{}) (string, error) {
	if t.ProtoWallet != nil {
		// ProtoWallet doesn't implement this method
		return "test", nil
	}
	return t.Wallet.GetNetwork(args)
}

// GetVersion delegates to the appropriate wallet implementation
func (t *TestWalletInterface) GetVersion(args interface{}) (string, error) {
	if t.ProtoWallet != nil {
		// ProtoWallet doesn't implement this method
		return "1.0.0", nil
	}
	return t.Wallet.GetVersion(args)
}
