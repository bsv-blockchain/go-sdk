package registry

import (
	"context"
	"testing"

	"github.com/bsv-blockchain/go-sdk/v2/wallet"
	"github.com/stretchr/testify/require"
)

// MockRegistry implements the wallet.Wallet interface for testing purposes
type MockRegistry struct {
	T                          *testing.T
	ExpectedOriginator         string
	ExpectedCreateActionArgs   *wallet.CreateActionArgs
	CreateActionResultToReturn *wallet.CreateActionResult
	SignActionResultToReturn   *wallet.SignActionResult
	ListOutputsResultToReturn  *wallet.ListOutputsResult

	// Add these fields for custom test behavior
	GetPublicKeyResult    *wallet.GetPublicKeyResult
	GetPublicKeyError     error
	CreateSignatureResult *wallet.CreateSignatureResult
	CreateSignatureError  error
}

// NewMockRegistry creates a new MockRegistry
func NewMockRegistry(t *testing.T) *MockRegistry {
	return &MockRegistry{T: t}
}

// All Wallet interface methods

func (m *MockRegistry) CreateAction(ctx context.Context, args wallet.CreateActionArgs, originator string) (*wallet.CreateActionResult, error) {
	if m.ExpectedCreateActionArgs != nil {
		require.Equal(m.T, m.ExpectedCreateActionArgs.Description, args.Description)
		require.Equal(m.T, m.ExpectedCreateActionArgs.Outputs, args.Outputs)
		require.Equal(m.T, m.ExpectedCreateActionArgs.Labels, args.Labels)
	}
	if m.ExpectedOriginator != "" {
		require.Equal(m.T, m.ExpectedOriginator, originator)
	}
	return m.CreateActionResultToReturn, nil
}

func (m *MockRegistry) SignAction(ctx context.Context, args wallet.SignActionArgs, originator string) (*wallet.SignActionResult, error) {
	if m.SignActionResultToReturn != nil {
		return m.SignActionResultToReturn, nil
	}
	require.Fail(m.T, "SignAction mock not implemented")
	return nil, nil
}

func (m *MockRegistry) AbortAction(ctx context.Context, args wallet.AbortActionArgs, originator string) (*wallet.AbortActionResult, error) {
	require.Fail(m.T, "AbortAction mock not implemented")
	return nil, nil
}

func (m *MockRegistry) ListActions(ctx context.Context, args wallet.ListActionsArgs, originator string) (*wallet.ListActionsResult, error) {
	require.Fail(m.T, "ListActions mock not implemented")
	return nil, nil
}

func (m *MockRegistry) InternalizeAction(ctx context.Context, args wallet.InternalizeActionArgs, originator string) (*wallet.InternalizeActionResult, error) {
	require.Fail(m.T, "InternalizeAction mock not implemented")
	return nil, nil
}

func (m *MockRegistry) ListOutputs(ctx context.Context, args wallet.ListOutputsArgs, originator string) (*wallet.ListOutputsResult, error) {
	if m.ListOutputsResultToReturn != nil {
		return m.ListOutputsResultToReturn, nil
	}
	require.Fail(m.T, "ListOutputs mock not implemented")
	return nil, nil
}

func (m *MockRegistry) RelinquishOutput(ctx context.Context, args wallet.RelinquishOutputArgs, originator string) (*wallet.RelinquishOutputResult, error) {
	require.Fail(m.T, "RelinquishOutput mock not implemented")
	return nil, nil
}

func (m *MockRegistry) GetPublicKey(ctx context.Context, args wallet.GetPublicKeyArgs, originator string) (*wallet.GetPublicKeyResult, error) {
	if m.GetPublicKeyResult != nil || m.GetPublicKeyError != nil {
		return m.GetPublicKeyResult, m.GetPublicKeyError
	}
	require.Fail(m.T, "GetPublicKey mock not implemented")
	return nil, nil
}

func (m *MockRegistry) RevealCounterpartyKeyLinkage(ctx context.Context, args wallet.RevealCounterpartyKeyLinkageArgs, originator string) (*wallet.RevealCounterpartyKeyLinkageResult, error) {
	require.Fail(m.T, "RevealCounterpartyKeyLinkage mock not implemented")
	return nil, nil
}

func (m *MockRegistry) RevealSpecificKeyLinkage(ctx context.Context, args wallet.RevealSpecificKeyLinkageArgs, originator string) (*wallet.RevealSpecificKeyLinkageResult, error) {
	require.Fail(m.T, "RevealSpecificKeyLinkage mock not implemented")
	return nil, nil
}

func (m *MockRegistry) Encrypt(ctx context.Context, args wallet.EncryptArgs, originator string) (*wallet.EncryptResult, error) {
	require.Fail(m.T, "Encrypt mock not implemented")
	return nil, nil
}

func (m *MockRegistry) Decrypt(ctx context.Context, args wallet.DecryptArgs, originator string) (*wallet.DecryptResult, error) {
	require.Fail(m.T, "Decrypt mock not implemented")
	return nil, nil
}

func (m *MockRegistry) CreateHMAC(ctx context.Context, args wallet.CreateHMACArgs, originator string) (*wallet.CreateHMACResult, error) {
	require.Fail(m.T, "CreateHMAC mock not implemented")
	return nil, nil
}

func (m *MockRegistry) VerifyHMAC(ctx context.Context, args wallet.VerifyHMACArgs, originator string) (*wallet.VerifyHMACResult, error) {
	require.Fail(m.T, "VerifyHMAC mock not implemented")
	return nil, nil
}

func (m *MockRegistry) CreateSignature(ctx context.Context, args wallet.CreateSignatureArgs, originator string) (*wallet.CreateSignatureResult, error) {
	if m.CreateSignatureResult != nil || m.CreateSignatureError != nil {
		return m.CreateSignatureResult, m.CreateSignatureError
	}
	require.Fail(m.T, "CreateSignature mock not implemented")
	return nil, nil
}

func (m *MockRegistry) VerifySignature(ctx context.Context, args wallet.VerifySignatureArgs, originator string) (*wallet.VerifySignatureResult, error) {
	require.Fail(m.T, "VerifySignature mock not implemented")
	return nil, nil
}

func (m *MockRegistry) AcquireCertificate(ctx context.Context, args wallet.AcquireCertificateArgs, originator string) (*wallet.Certificate, error) {
	require.Fail(m.T, "AcquireCertificate mock not implemented")
	return nil, nil
}

func (m *MockRegistry) ListCertificates(ctx context.Context, args wallet.ListCertificatesArgs, originator string) (*wallet.ListCertificatesResult, error) {
	require.Fail(m.T, "ListCertificates mock not implemented")
	return nil, nil
}

func (m *MockRegistry) ProveCertificate(ctx context.Context, args wallet.ProveCertificateArgs, originator string) (*wallet.ProveCertificateResult, error) {
	require.Fail(m.T, "ProveCertificate mock not implemented")
	return nil, nil
}

func (m *MockRegistry) RelinquishCertificate(ctx context.Context, args wallet.RelinquishCertificateArgs, originator string) (*wallet.RelinquishCertificateResult, error) {
	require.Fail(m.T, "RelinquishCertificate mock not implemented")
	return nil, nil
}

func (m *MockRegistry) DiscoverByIdentityKey(ctx context.Context, args wallet.DiscoverByIdentityKeyArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	require.Fail(m.T, "DiscoverByIdentityKey mock not implemented")
	return nil, nil
}

func (m *MockRegistry) DiscoverByAttributes(ctx context.Context, args wallet.DiscoverByAttributesArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	require.Fail(m.T, "DiscoverByAttributes mock not implemented")
	return nil, nil
}

func (m *MockRegistry) IsAuthenticated(ctx context.Context, args any, originator string) (*wallet.AuthenticatedResult, error) {
	require.Fail(m.T, "IsAuthenticated mock not implemented")
	return nil, nil
}

func (m *MockRegistry) WaitForAuthentication(ctx context.Context, args any, originator string) (*wallet.AuthenticatedResult, error) {
	require.Fail(m.T, "WaitForAuthentication mock not implemented")
	return nil, nil
}

func (m *MockRegistry) GetHeight(ctx context.Context, args any, originator string) (*wallet.GetHeightResult, error) {
	require.Fail(m.T, "GetHeight mock not implemented")
	return nil, nil
}

func (m *MockRegistry) GetHeaderForHeight(ctx context.Context, args wallet.GetHeaderArgs, originator string) (*wallet.GetHeaderResult, error) {
	require.Fail(m.T, "GetHeaderForHeight mock not implemented")
	return nil, nil
}

func (m *MockRegistry) GetNetwork(ctx context.Context, args any, originator string) (*wallet.GetNetworkResult, error) {
	require.Fail(m.T, "GetNetwork mock not implemented")
	return nil, nil
}

func (m *MockRegistry) GetVersion(ctx context.Context, args any, originator string) (*wallet.GetVersionResult, error) {
	require.Fail(m.T, "GetVersion mock not implemented")
	return nil, nil
}
