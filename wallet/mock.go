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

func (m *MockWallet) CreateAction(args CreateActionArgs, originator string) (*CreateActionResult, error) {
	if m.ExpectedCreateActionArgs != nil {
		require.Equal(m.T, m.ExpectedCreateActionArgs.Description, args.Description)
		require.Equal(m.T, m.ExpectedCreateActionArgs.Outputs, args.Outputs)
		require.Equal(m.T, m.ExpectedCreateActionArgs.Labels, args.Labels)
	}
	require.Equal(m.T, m.ExpectedOriginator, originator)
	return m.CreateActionResultToReturn, nil
}

func (m *MockWallet) SignAction(args SignActionArgs, originator string) (*SignActionResult, error) {
	require.Fail(m.T, "SignAction mock not implemented")
	return nil, nil
}

func (m *MockWallet) AbortAction(args AbortActionArgs, originator string) (*AbortActionResult, error) {
	require.Fail(m.T, "AbortAction mock not implemented")
	return nil, nil
}

func (m *MockWallet) ListActions(args ListActionsArgs, originator string) (*ListActionsResult, error) {
	require.Fail(m.T, "ListActions mock not implemented")
	return nil, nil
}

func (m *MockWallet) InternalizeAction(args InternalizeActionArgs, originator string) (*InternalizeActionResult, error) {
	require.Fail(m.T, "InternalizeAction mock not implemented")
	return nil, nil
}

func (m *MockWallet) ListOutputs(args ListOutputsArgs, originator string) (*ListOutputsResult, error) {
	require.Fail(m.T, "ListOutputs mock not implemented")
	return nil, nil
}

func (m *MockWallet) RelinquishOutput(args RelinquishOutputArgs, originator string) (*RelinquishOutputResult, error) {
	require.Fail(m.T, "RelinquishOutput mock not implemented")
	return nil, nil
}

func (m *MockWallet) GetPublicKey(args GetPublicKeyArgs, originator string) (*GetPublicKeyResult, error) {
	require.Fail(m.T, "GetPublicKey mock not implemented")
	return nil, nil
}

func (m *MockWallet) RevealCounterpartyKeyLinkage(args RevealCounterpartyKeyLinkageArgs, originator string) (*RevealCounterpartyKeyLinkageResult, error) {
	require.Fail(m.T, "RevealCounterpartyKeyLinkage mock not implemented")
	return nil, nil
}

func (m *MockWallet) RevealSpecificKeyLinkage(args RevealSpecificKeyLinkageArgs, originator string) (*RevealSpecificKeyLinkageResult, error) {
	require.Fail(m.T, "RevealSpecificKeyLinkage mock not implemented")
	return nil, nil
}

func (m *MockWallet) Encrypt(args EncryptArgs, originator string) (*EncryptResult, error) {
	require.Fail(m.T, "Encrypt mock not implemented")
	return nil, nil
}

func (m *MockWallet) Decrypt(args DecryptArgs, originator string) (*DecryptResult, error) {
	require.Fail(m.T, "Decrypt mock not implemented")
	return nil, nil
}

func (m *MockWallet) CreateHmac(args CreateHmacArgs, originator string) (*CreateHmacResult, error) {
	require.Fail(m.T, "CreateHmac mock not implemented")
	return nil, nil
}

func (m *MockWallet) VerifyHmac(args VerifyHmacArgs, originator string) (*VerifyHmacResult, error) {
	require.Fail(m.T, "VerifyHmac mock not implemented")
	return nil, nil
}

func (m *MockWallet) CreateSignature(args CreateSignatureArgs, originator string) (*CreateSignatureResult, error) {
	require.Fail(m.T, "CreateSignature mock not implemented")
	return nil, nil
}

func (m *MockWallet) VerifySignature(args VerifySignatureArgs, originator string) (*VerifySignatureResult, error) {
	require.Fail(m.T, "VerifySignature mock not implemented")
	return nil, nil
}

func (m *MockWallet) AcquireCertificate(args AcquireCertificateArgs, originator string) (*Certificate, error) {
	require.Fail(m.T, "AcquireCertificate mock not implemented")
	return nil, nil
}

func (m *MockWallet) ListCertificates(args ListCertificatesArgs, originator string) (*ListCertificatesResult, error) {
	require.Fail(m.T, "ListCertificates mock not implemented")
	return nil, nil
}

func (m *MockWallet) ProveCertificate(args ProveCertificateArgs, originator string) (*ProveCertificateResult, error) {
	require.Fail(m.T, "ProveCertificate mock not implemented")
	return nil, nil
}

func (m *MockWallet) RelinquishCertificate(args RelinquishCertificateArgs, originator string) (*RelinquishCertificateResult, error) {
	require.Fail(m.T, "RelinquishCertificate mock not implemented")
	return nil, nil
}

func (m *MockWallet) DiscoverByIdentityKey(args DiscoverByIdentityKeyArgs, originator string) (*DiscoverCertificatesResult, error) {
	require.Fail(m.T, "DiscoverByIdentityKey mock not implemented")
	return nil, nil
}

func (m *MockWallet) DiscoverByAttributes(args DiscoverByAttributesArgs, originator string) (*DiscoverCertificatesResult, error) {
	require.Fail(m.T, "DiscoverByAttributes mock not implemented")
	return nil, nil
}

func (m *MockWallet) IsAuthenticated(args interface{}, originator string) (*AuthenticatedResult, error) {
	require.Fail(m.T, "IsAuthenticated mock not implemented")
	return nil, nil
}

func (m *MockWallet) WaitForAuthentication(args interface{}, originator string) (*AuthenticatedResult, error) {
	require.Fail(m.T, "WaitForAuthentication mock not implemented")
	return nil, nil
}

func (m *MockWallet) GetHeight(args interface{}, originator string) (*GetHeightResult, error) {
	require.Fail(m.T, "GetHeight mock not implemented")
	return nil, nil
}

func (m *MockWallet) GetHeaderForHeight(args GetHeaderArgs, originator string) (*GetHeaderResult, error) {
	require.Fail(m.T, "GetHeaderForHeight mock not implemented")
	return nil, nil
}

func (m *MockWallet) GetNetwork(args interface{}, originator string) (*GetNetworkResult, error) {
	require.Fail(m.T, "GetNetwork mock not implemented")
	return nil, nil
}

func (m *MockWallet) GetVersion(args interface{}, originator string) (*GetVersionResult, error) {
	require.Fail(m.T, "GetVersion mock not implemented")
	return nil, nil
}
