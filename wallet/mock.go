package wallet

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type MockWallet struct {
	T                          *testing.T
	ExpectedOriginator         string
	ExpectedCreateActionArgs   *CreateActionArgs
	CreateActionResultToReturn *CreateActionResult
	CreateActionError          error

	// Added for kvstore tests
	ListOutputsResultToReturn      *ListOutputsResult
	ListOutputsError               error
	EncryptResultToReturn          *EncryptResult
	EncryptError                   error
	SignActionResultToReturn       *SignActionResult
	SignActionError                error
	RelinquishOutputResultToReturn *RelinquishOutputResult
	RelinquishOutputError          error
	RelinquishOutputCalledCount    int // Track calls

	// Existing fields for other tests
	ListCertificatesResult *ListCertificatesResult
	ListCertificatesError  error
	ProveCertificateResult *ProveCertificateResult
	ProveCertificateError  error
	GetPublicKeyResult     *GetPublicKeyResult
	GetPublicKeyError      error
	CreateHmacResult       *CreateHMACResult
	CreateHmacError        error
	CreateSignatureResult  *CreateSignatureResult
	CreateSignatureError   error
	VerifySignatureResult  *VerifySignatureResult
	VerifySignatureError   error
	DecryptResult          *DecryptResult
	DecryptError           error
	// Function implementations for methods needed by identity client tests
	MockProveCertificate      func(ctx context.Context, args ProveCertificateArgs, originator string) (*ProveCertificateResult, error)
	MockCreateAction          func(ctx context.Context, args CreateActionArgs, originator string) (*CreateActionResult, error)
	MockGetNetwork            func(ctx context.Context, args any, originator string) (*GetNetworkResult, error)
	MockDiscoverByIdentityKey func(ctx context.Context, args DiscoverByIdentityKeyArgs, originator string) (*DiscoverCertificatesResult, error)
	MockDiscoverByAttributes  func(ctx context.Context, args DiscoverByAttributesArgs, originator string) (*DiscoverCertificatesResult, error)
	MockGetPublicKey          func(ctx context.Context, args GetPublicKeyArgs, originator string) (*GetPublicKeyResult, error)
	MockCreateSignature       func(ctx context.Context, args CreateSignatureArgs, originator string) (*CreateSignatureResult, error)
	MockCreateHmac            func(ctx context.Context, args CreateHMACArgs, originator string) (*CreateHMACResult, error)
	MockDecrypt               func(ctx context.Context, args DecryptArgs, originator string) (*DecryptResult, error)
	MockVerifySignature       func(ctx context.Context, args VerifySignatureArgs, originator string) (*VerifySignatureResult, error)
	MockListCertificates      func(ctx context.Context, args ListCertificatesArgs, originator string) (*ListCertificatesResult, error)
}

func NewMockWallet(t *testing.T) *MockWallet {
	return &MockWallet{T: t}
}

func (m *MockWallet) CreateAction(ctx context.Context, args CreateActionArgs, originator string) (*CreateActionResult, error) {
	if m.CreateActionError != nil {
		return nil, m.CreateActionError
	}
	// Use MockCreateAction if provided, but don't remove the existing functionality
	if m.MockCreateAction != nil {
		return m.MockCreateAction(ctx, args, originator)
	}

	if m.ExpectedCreateActionArgs != nil {
		require.Equal(m.T, m.ExpectedCreateActionArgs.Description, args.Description)
		require.Equal(m.T, m.ExpectedCreateActionArgs.Outputs, args.Outputs)
		require.Equal(m.T, m.ExpectedCreateActionArgs.Labels, args.Labels)
	}
	if m.ExpectedOriginator != "" {
		require.Equal(m.T, m.ExpectedOriginator, originator)
	}
	if m.CreateActionResultToReturn == nil {
		return &CreateActionResult{}, nil
	}
	return m.CreateActionResultToReturn, nil
}

func (m *MockWallet) SignAction(ctx context.Context, args SignActionArgs, originator string) (*SignActionResult, error) {
	if m.SignActionError != nil {
		return nil, m.SignActionError
	}
	if m.SignActionResultToReturn == nil {
		return &SignActionResult{}, nil
	}
	return m.SignActionResultToReturn, nil
}

func (m *MockWallet) ListOutputs(ctx context.Context, args ListOutputsArgs, originator string) (*ListOutputsResult, error) {
	if m.ListOutputsResultToReturn == nil {
		return &ListOutputsResult{Outputs: []Output{}}, nil
	}
	if m.ListOutputsError != nil {
		return nil, m.ListOutputsError
	}
	return m.ListOutputsResultToReturn, nil
}

func (m *MockWallet) Encrypt(ctx context.Context, args EncryptArgs, originator string) (*EncryptResult, error) {
	if m.EncryptError != nil {
		return nil, m.EncryptError
	}
	if m.EncryptResultToReturn == nil {
		return &EncryptResult{}, nil
	}
	return m.EncryptResultToReturn, nil
}

func (m *MockWallet) Decrypt(ctx context.Context, args DecryptArgs, originator string) (*DecryptResult, error) {
	if m.MockDecrypt != nil {
		return m.MockDecrypt(ctx, args, originator)
	}
	if m.DecryptError != nil {
		return nil, m.DecryptError
	}
	if m.DecryptResult == nil {
		return &DecryptResult{}, nil
	}
	return m.DecryptResult, nil
}

func (m *MockWallet) GetPublicKey(ctx context.Context, args GetPublicKeyArgs, originator string) (*GetPublicKeyResult, error) {
	if m.MockGetPublicKey != nil {
		return m.MockGetPublicKey(ctx, args, originator)
	}

	if m.GetPublicKeyError != nil {
		return nil, m.GetPublicKeyError
	}
	if m.GetPublicKeyResult == nil {
		require.Fail(m.T, "GetPublicKey mock called but GetPublicKeyResult not set")
		return nil, errors.New("GetPublicKey mock result not configured")
	}
	return m.GetPublicKeyResult, nil
}

func (m *MockWallet) CreateSignature(ctx context.Context, args CreateSignatureArgs, originator string) (*CreateSignatureResult, error) {
	if m.MockCreateSignature != nil {
		return m.MockCreateSignature(ctx, args, originator)
	}
	if m.CreateSignatureError != nil {
		return nil, m.CreateSignatureError
	}
	if m.CreateSignatureResult == nil {
		require.Fail(m.T, "CreateSignature mock called but CreateSignatureResult not set")
		return nil, errors.New("CreateSignature mock result not configured")
	}
	return m.CreateSignatureResult, nil
}

func (m *MockWallet) RelinquishOutput(ctx context.Context, args RelinquishOutputArgs, originator string) (*RelinquishOutputResult, error) {
	m.RelinquishOutputCalledCount++ // Increment counter
	if m.RelinquishOutputError != nil {
		return nil, m.RelinquishOutputError
	}
	if m.RelinquishOutputResultToReturn == nil {
		// Default success if no specific result is set
		return &RelinquishOutputResult{Relinquished: true}, nil
	}
	return m.RelinquishOutputResultToReturn, nil
}

func (m *MockWallet) AbortAction(ctx context.Context, args AbortActionArgs, originator string) (*AbortActionResult, error) {
	require.Fail(m.T, "AbortAction mock not implemented")
	return nil, errors.New("AbortAction mock not implemented")
}

func (m *MockWallet) ListActions(ctx context.Context, args ListActionsArgs, originator string) (*ListActionsResult, error) {
	require.Fail(m.T, "ListActions mock not implemented")
	return nil, errors.New("ListActions mock not implemented")
}

func (m *MockWallet) InternalizeAction(ctx context.Context, args InternalizeActionArgs, originator string) (*InternalizeActionResult, error) {
	require.Fail(m.T, "InternalizeAction mock not implemented")
	return nil, errors.New("InternalizeAction mock not implemented")
}

func (m *MockWallet) RevealCounterpartyKeyLinkage(ctx context.Context, args RevealCounterpartyKeyLinkageArgs, originator string) (*RevealCounterpartyKeyLinkageResult, error) {
	require.Fail(m.T, "RevealCounterpartyKeyLinkage mock not implemented")
	return nil, errors.New("RevealCounterpartyKeyLinkage mock not implemented")
}

func (m *MockWallet) RevealSpecificKeyLinkage(ctx context.Context, args RevealSpecificKeyLinkageArgs, originator string) (*RevealSpecificKeyLinkageResult, error) {
	require.Fail(m.T, "RevealSpecificKeyLinkage mock not implemented")
	return nil, errors.New("RevealSpecificKeyLinkage mock not implemented")
}

func (m *MockWallet) CreateHMAC(ctx context.Context, args CreateHMACArgs, originator string) (*CreateHMACResult, error) {
	if m.MockCreateHmac != nil {
		return m.MockCreateHmac(ctx, args, originator)
	}
	if m.CreateHmacResult == nil {
		require.Fail(m.T, "CreateHMAC mock called but CreateHMACResult not set")
		return nil, errors.New("CreateHMAC mock result not configured")
	}
	if m.CreateHmacError != nil {
		return nil, m.CreateHmacError
	}
	return m.CreateHmacResult, nil
}

func (m *MockWallet) VerifyHMAC(ctx context.Context, args VerifyHMACArgs, originator string) (*VerifyHMACResult, error) {
	require.Fail(m.T, "VerifyHMAC mock not implemented")
	return nil, errors.New("VerifyHMAC mock not implemented")
}

func (m *MockWallet) VerifySignature(ctx context.Context, args VerifySignatureArgs, originator string) (*VerifySignatureResult, error) {
	if m.MockVerifySignature != nil {
		return m.MockVerifySignature(ctx, args, originator)
	}
	if m.VerifySignatureResult == nil {
		return &VerifySignatureResult{Valid: true}, nil
	}
	if m.VerifySignatureError != nil {
		return nil, m.VerifySignatureError
	}
	return m.VerifySignatureResult, nil
}

func (m *MockWallet) AcquireCertificate(ctx context.Context, args AcquireCertificateArgs, originator string) (*Certificate, error) {
	require.Fail(m.T, "AcquireCertificate mock not implemented")
	return nil, errors.New("AcquireCertificate mock not implemented")
}

func (m *MockWallet) ListCertificates(ctx context.Context, args ListCertificatesArgs, originator string) (*ListCertificatesResult, error) {
	if m.ListCertificatesError != nil {
		return nil, m.ListCertificatesError
	}
	if m.MockListCertificates != nil {
		return m.MockListCertificates(ctx, args, originator)
	}
	if m.ListCertificatesResult == nil {
		return &ListCertificatesResult{Certificates: []CertificateResult{}}, nil
	}
	return m.ListCertificatesResult, nil
}

func (m *MockWallet) ProveCertificate(ctx context.Context, args ProveCertificateArgs, originator string) (*ProveCertificateResult, error) {
	if m.ProveCertificateError != nil {
		return nil, m.ProveCertificateError
	}
	if m.MockProveCertificate != nil {
		return m.MockProveCertificate(ctx, args, originator)
	}
	if m.ProveCertificateResult == nil {
		return &ProveCertificateResult{}, nil
	}
	return m.ProveCertificateResult, nil
}

func (m *MockWallet) RelinquishCertificate(ctx context.Context, args RelinquishCertificateArgs, originator string) (*RelinquishCertificateResult, error) {
	require.Fail(m.T, "RelinquishCertificate mock not implemented")
	return nil, errors.New("RelinquishCertificate mock not implemented")
}

func (m *MockWallet) DiscoverByIdentityKey(ctx context.Context, args DiscoverByIdentityKeyArgs, originator string) (*DiscoverCertificatesResult, error) {
	if m.MockDiscoverByIdentityKey != nil {
		return m.MockDiscoverByIdentityKey(ctx, args, originator)
	}
	require.Fail(m.T, "DiscoverByIdentityKey mock not implemented")
	return nil, errors.New("DiscoverByIdentityKey mock not implemented")
}

func (m *MockWallet) DiscoverByAttributes(ctx context.Context, args DiscoverByAttributesArgs, originator string) (*DiscoverCertificatesResult, error) {
	if m.MockDiscoverByAttributes != nil {
		return m.MockDiscoverByAttributes(ctx, args, originator)
	}
	require.Fail(m.T, "DiscoverByAttributes mock not implemented")
	return nil, errors.New("DiscoverByAttributes mock not implemented")
}

func (m *MockWallet) IsAuthenticated(ctx context.Context, args any, originator string) (*AuthenticatedResult, error) {
	require.Fail(m.T, "IsAuthenticated mock not implemented")
	return nil, errors.New("IsAuthenticated mock not implemented")
}

func (m *MockWallet) WaitForAuthentication(ctx context.Context, args any, originator string) (*AuthenticatedResult, error) {
	require.Fail(m.T, "WaitForAuthentication mock not implemented")
	return nil, errors.New("WaitForAuthentication mock not implemented")
}

func (m *MockWallet) GetHeight(ctx context.Context, args any, originator string) (*GetHeightResult, error) {
	require.Fail(m.T, "GetHeight mock not implemented")
	return nil, errors.New("GetHeight mock not implemented")
}

func (m *MockWallet) GetHeaderForHeight(ctx context.Context, args GetHeaderArgs, originator string) (*GetHeaderResult, error) {
	require.Fail(m.T, "GetHeaderForHeight mock not implemented")
	return nil, errors.New("GetHeaderForHeight mock not implemented")
}

func (m *MockWallet) GetNetwork(ctx context.Context, args any, originator string) (*GetNetworkResult, error) {
	if m.MockGetNetwork != nil {
		return m.MockGetNetwork(ctx, args, originator)
	}
	require.Fail(m.T, "GetNetwork mock not implemented")
	return nil, errors.New("GetNetwork mock not implemented")
}

func (m *MockWallet) GetVersion(ctx context.Context, args any, originator string) (*GetVersionResult, error) {
	require.Fail(m.T, "GetVersion mock not implemented")
	return nil, errors.New("GetVersion mock not implemented")
}
