package clients

import (
	"context"
	"testing"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

// MockSessionManager implements auth.SessionManager for testing
type MockSessionManager struct {
	Sessions map[string]*auth.PeerSession
}

func NewMockSessionManager() *MockSessionManager {
	return &MockSessionManager{
		Sessions: make(map[string]*auth.PeerSession),
	}
}

func (m *MockSessionManager) AddSession(session *auth.PeerSession) error {
	m.Sessions[session.SessionNonce] = session
	return nil
}

func (m *MockSessionManager) UpdateSession(session *auth.PeerSession) {
	m.Sessions[session.SessionNonce] = session
}

func (m *MockSessionManager) GetSession(identifier string) (*auth.PeerSession, error) {
	if session, ok := m.Sessions[identifier]; ok {
		return session, nil
	}
	return nil, auth.ErrSessionNotFound
}

func (m *MockSessionManager) RemoveSession(session *auth.PeerSession) {
	delete(m.Sessions, session.SessionNonce)
}

func (m *MockSessionManager) HasSession(identifier string) bool {
	_, exists := m.Sessions[identifier]
	return exists
}

// TestNew tests the New function
func TestNew(t *testing.T) {
	// Set up dependencies
	mockWallet := wallet.NewTestWalletForRandomKey(t)
	mockSessionManager := NewMockSessionManager()
	requestedCerts := &utils.RequestedCertificateSet{
		Certifiers:       []*ec.PublicKey{},
		CertificateTypes: make(utils.RequestedCertificateTypeIDAndFieldList),
	}

	// Create AuthFetch instance
	authFetch := New(mockWallet, requestedCerts, mockSessionManager)

	// Assertions
	require.NotNil(t, authFetch)
	require.Equal(t, mockWallet, authFetch.wallet)
	require.Equal(t, mockSessionManager, authFetch.sessionManager)
	require.Equal(t, requestedCerts, authFetch.requestedCertificates)
	require.Empty(t, authFetch.peers)
	require.Empty(t, authFetch.certificatesReceived)
}

// TestNewWithNilSessionManager tests the New function with a nil session manager
func TestNewWithNilSessionManager(t *testing.T) {
	// Set up dependencies
	mockWallet := wallet.NewTestWalletForRandomKey(t)
	requestedCerts := &utils.RequestedCertificateSet{
		Certifiers:       []*ec.PublicKey{},
		CertificateTypes: make(utils.RequestedCertificateTypeIDAndFieldList),
	}

	// Create AuthFetch instance with nil session manager
	authFetch := New(mockWallet, requestedCerts, nil)

	// Assertions
	require.NotNil(t, authFetch)
	require.NotNil(t, authFetch.sessionManager)
}

// TestConsumeReceivedCertificates tests the ConsumeReceivedCertificates method
func TestConsumeReceivedCertificates(t *testing.T) {
	// Set up dependencies
	mockWallet := wallet.NewTestWalletForRandomKey(t)
	mockSessionManager := NewMockSessionManager()
	requestedCerts := &utils.RequestedCertificateSet{}

	// Create AuthFetch instance
	authFetch := New(mockWallet, requestedCerts, mockSessionManager)

	// Add some mock certificates
	cert1 := &certificates.VerifiableCertificate{}
	cert2 := &certificates.VerifiableCertificate{}
	authFetch.certificatesReceived = []*certificates.VerifiableCertificate{cert1, cert2}

	// Consume certificates
	receivedCerts := authFetch.ConsumeReceivedCertificates()

	require.Len(t, receivedCerts, 2)
	require.Contains(t, receivedCerts, cert1)
	require.Contains(t, receivedCerts, cert2)
	require.Empty(t, authFetch.certificatesReceived)
}

// TestFetchWithRetryCounterAtZero tests the Fetch method with retry counter at 0
func TestFetchWithRetryCounterAtZero(t *testing.T) {
	// Set up dependencies
	mockWallet := wallet.NewTestWalletForRandomKey(t)
	mockSessionManager := NewMockSessionManager()
	requestedCerts := &utils.RequestedCertificateSet{}

	// Create AuthFetch instance
	authFetch := New(mockWallet, requestedCerts, mockSessionManager)

	// Set up test parameters
	ctx := context.Background()
	url := "https://example.com"
	retryCounter := 0
	config := &SimplifiedFetchRequestOptions{
		Method:       "GET",
		RetryCounter: &retryCounter,
	}

	// Call Fetch
	resp, err := authFetch.Fetch(ctx, url, config)

	require.Error(t, err)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "maximum number of retries")
}
