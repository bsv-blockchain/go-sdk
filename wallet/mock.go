package wallet

import (
	"context"
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

func (m *MockWallet) CreateAction(ctx context.Context, args CreateActionArgs, originator string) (*CreateActionResult, error) {
	if m.ExpectedCreateActionArgs != nil {
		require.Equal(m.T, m.ExpectedCreateActionArgs.Description, args.Description)
		require.Equal(m.T, m.ExpectedCreateActionArgs.Outputs, args.Outputs)
		require.Equal(m.T, m.ExpectedCreateActionArgs.Labels, args.Labels)
	}
	require.Equal(m.T, m.ExpectedOriginator, originator)
	return m.CreateActionResultToReturn, nil
}

func (m *MockWallet) SignAction(ctx context.Context, args SignActionArgs, originator string) (*SignActionResult, error) {
	require.Fail(m.T, "SignAction mock not implemented")
	return nil, nil
}

func (m *MockWallet) AbortAction(ctx context.Context, args AbortActionArgs, originator string) (*AbortActionResult, error) {
	require.Fail(m.T, "AbortAction mock not implemented")
	return nil, nil
}

func (m *MockWallet) ListActions(ctx context.Context, args ListActionsArgs, originator string) (*ListActionsResult, error) {
	require.Fail(m.T, "ListActions mock not implemented")
	return nil, nil
}

func (m *MockWallet) InternalizeAction(ctx context.Context, args InternalizeActionArgs, originator string) (*InternalizeActionResult, error) {
	require.Fail(m.T, "InternalizeAction mock not implemented")
	return nil, nil
}

func (m *MockWallet) ListOutputs(ctx context.Context, args ListOutputsArgs, originator string) (*ListOutputsResult, error) {
	require.Fail(m.T, "ListOutputs mock not implemented")
	return nil, nil
}

func (m *MockWallet) RelinquishOutput(ctx context.Context, args RelinquishOutputArgs, originator string) (*RelinquishOutputResult, error) {
	require.Fail(m.T, "RelinquishOutput mock not implemented")
	return nil, nil
}

func (m *MockWallet) GetPublicKey(ctx context.Context, args GetPublicKeyArgs, originator string) (*GetPublicKeyResult, error) {
	require.Fail(m.T, "GetPublicKey mock not implemented")
	return nil, nil
}

func (m *MockWallet) RevealCounterpartyKeyLinkage(ctx context.Context, args RevealCounterpartyKeyLinkageArgs, originator string) (*RevealCounterpartyKeyLinkageResult, error) {
	require.Fail(m.T, "RevealCounterpartyKeyLinkage mock not implemented")
	return nil, nil
}

func (m *MockWallet) RevealSpecificKeyLinkage(ctx context.Context, args RevealSpecificKeyLinkageArgs, originator string) (*RevealSpecificKeyLinkageResult, error) {
	require.Fail(m.T, "RevealSpecificKeyLinkage mock not implemented")
	return nil, nil
}

func (m *MockWallet) Encrypt(ctx context.Context, args EncryptArgs, originator string) (*EncryptResult, error) {
	require.Fail(m.T, "Encrypt mock not implemented")
	return nil, nil
}

func (m *MockWallet) Decrypt(ctx context.Context, args DecryptArgs, originator string) (*DecryptResult, error) {
	require.Fail(m.T, "Decrypt mock not implemented")
	return nil, nil
}

func (m *MockWallet) CreateHmac(ctx context.Context, args CreateHmacArgs, originator string) (*CreateHmacResult, error) {
	require.Fail(m.T, "CreateHmac mock not implemented")
	return nil, nil
}

func (m *MockWallet) VerifyHmac(ctx context.Context, args VerifyHmacArgs, originator string) (*VerifyHmacResult, error) {
	require.Fail(m.T, "VerifyHmac mock not implemented")
	return nil, nil
}

func (m *MockWallet) CreateSignature(ctx context.Context, args CreateSignatureArgs, originator string) (*CreateSignatureResult, error) {
	require.Fail(m.T, "CreateSignature mock not implemented")
	return nil, nil
}

func (m *MockWallet) VerifySignature(ctx context.Context, args VerifySignatureArgs, originator string) (*VerifySignatureResult, error) {
	require.Fail(m.T, "VerifySignature mock not implemented")
	return nil, nil
}

func (m *MockWallet) AcquireCertificate(ctx context.Context, args AcquireCertificateArgs, originator string) (*Certificate, error) {
	require.Fail(m.T, "AcquireCertificate mock not implemented")
	return nil, nil
}

func (m *MockWallet) ListCertificates(ctx context.Context, args ListCertificatesArgs, originator string) (*ListCertificatesResult, error) {
	require.Fail(m.T, "ListCertificates mock not implemented")
	return nil, nil
}

func (m *MockWallet) ProveCertificate(ctx context.Context, args ProveCertificateArgs, originator string) (*ProveCertificateResult, error) {
	require.Fail(m.T, "ProveCertificate mock not implemented")
	return nil, nil
}

func (m *MockWallet) RelinquishCertificate(ctx context.Context, args RelinquishCertificateArgs, originator string) (*RelinquishCertificateResult, error) {
	require.Fail(m.T, "RelinquishCertificate mock not implemented")
	return nil, nil
}

func (m *MockWallet) DiscoverByIdentityKey(ctx context.Context, args DiscoverByIdentityKeyArgs, originator string) (*DiscoverCertificatesResult, error) {
	require.Fail(m.T, "DiscoverByIdentityKey mock not implemented")
	return nil, nil
}

func (m *MockWallet) DiscoverByAttributes(ctx context.Context, args DiscoverByAttributesArgs, originator string) (*DiscoverCertificatesResult, error) {
	require.Fail(m.T, "DiscoverByAttributes mock not implemented")
	return nil, nil
}

func (m *MockWallet) IsAuthenticated(ctx context.Context, args any, originator string) (*AuthenticatedResult, error) {
	require.Fail(m.T, "IsAuthenticated mock not implemented")
	return nil, nil
}

func (m *MockWallet) WaitForAuthentication(ctx context.Context, args any, originator string) (*AuthenticatedResult, error) {
	require.Fail(m.T, "WaitForAuthentication mock not implemented")
	return nil, nil
}

func (m *MockWallet) GetHeight(ctx context.Context, args any, originator string) (*GetHeightResult, error) {
	require.Fail(m.T, "GetHeight mock not implemented")
	return nil, nil
}

func (m *MockWallet) GetHeaderForHeight(ctx context.Context, args GetHeaderArgs, originator string) (*GetHeaderResult, error) {
	require.Fail(m.T, "GetHeaderForHeight mock not implemented")
	return nil, nil
}

func (m *MockWallet) GetNetwork(ctx context.Context, args any, originator string) (*GetNetworkResult, error) {
	require.Fail(m.T, "GetNetwork mock not implemented")
	return nil, nil
}

func (m *MockWallet) GetVersion(ctx context.Context, args any, originator string) (*GetVersionResult, error) {
	require.Fail(m.T, "GetVersion mock not implemented")
	return nil, nil
}
