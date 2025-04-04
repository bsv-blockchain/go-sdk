package wallet

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type MockWallet struct {
	T                          *testing.T
	ExpectedOriginator         string
	ExpectedCreateActionArgs   *CreateActionArgs
	CreateActionResultToReturn *CreateActionResult
}

func NewMockWallet(t *testing.T) *MockWallet {
	return &MockWallet{T: t}
}

// Required methods from Interface
func (m *MockWallet) CreateAction(args CreateActionArgs, originator string) (*CreateActionResult, error) {
	if m.ExpectedCreateActionArgs != nil {
		require.Equal(m.T, m.ExpectedCreateActionArgs.Description, args.Description)
		require.Equal(m.T, m.ExpectedCreateActionArgs.Outputs, args.Outputs)
		require.Equal(m.T, m.ExpectedCreateActionArgs.Labels, args.Labels)
	}
	require.Equal(m.T, m.ExpectedOriginator, originator)
	return m.CreateActionResultToReturn, nil
}

func (m *MockWallet) ListCertificates(args ListCertificatesArgs) (*ListCertificatesResult, error) {
	return &ListCertificatesResult{}, nil
}

func (m *MockWallet) ProveCertificate(args ProveCertificateArgs) (*ProveCertificateResult, error) {
	return &ProveCertificateResult{}, nil
}

func (m *MockWallet) CreateHmac(args CreateHmacArgs) (*CreateHmacResult, error) {
	return &CreateHmacResult{}, nil
}

func (m *MockWallet) VerifyHmac(args VerifyHmacArgs) (*VerifyHmacResult, error) {
	return &VerifyHmacResult{}, nil
}

func (m *MockWallet) CreateSignature(args *CreateSignatureArgs, originator string) (*CreateSignatureResult, error) {
	return &CreateSignatureResult{}, nil
}

func (m *MockWallet) VerifySignature(args *VerifySignatureArgs) (*VerifySignatureResult, error) {
	return &VerifySignatureResult{}, nil
}

func (m *MockWallet) Encrypt(args *EncryptArgs) (*EncryptResult, error) {
	return &EncryptResult{}, nil
}

func (m *MockWallet) Decrypt(args *DecryptArgs) (*DecryptResult, error) {
	return &DecryptResult{}, nil
}

func (m *MockWallet) GetPublicKey(args *GetPublicKeyArgs, originator string) (*GetPublicKeyResult, error) {
	return &GetPublicKeyResult{}, nil
}

func (m *MockWallet) IsAuthenticated(args interface{}) (bool, error) {
	return true, nil
}

func (m *MockWallet) GetHeight(args interface{}) (uint32, error) {
	return 0, nil
}

func (m *MockWallet) GetNetwork(args interface{}) (string, error) {
	return "", nil
}

func (m *MockWallet) GetVersion(args interface{}) (string, error) {
	return "", nil
}
