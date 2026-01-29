package clients

import (
	"context"
	"fmt"
	"net/http"
	"strings"
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
	authFetch := New(mockWallet, WithCertificatesToRequest(requestedCerts), WithSessionManager(mockSessionManager))

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
	authFetch := New(mockWallet, WithCertificatesToRequest(requestedCerts))

	// Assertions
	require.NotNil(t, authFetch)
	require.NotNil(t, authFetch.sessionManager)
}

type failingTransport struct {
	t testing.TB
}

func (f *failingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	require.Failf(f.t, "Request should not be made", "Unexpected request to: %s %s", req.Method, req.URL.String())
	return nil, fmt.Errorf("unexpected request")
}

func TestAuthFetchWithUnsupportedHeaders(t *testing.T) {
	tests := map[string]struct {
		headerName  string
		headerValue string
	}{
		"x-bsv-auth": {
			headerName:  "x-bsv-auth",
			headerValue: "123",
		},
		"custom header": {
			headerName:  "x-custom-header",
			headerValue: "123",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// given:
			mockWallet := wallet.NewTestWalletForRandomKey(t)

			// and:
			authFetch := New(mockWallet, WithHttpClientTransport(&failingTransport{t: t}))

			// when:
			_, err := authFetch.Fetch(t.Context(), "https://example.com", &SimplifiedFetchRequestOptions{
				Method: "GET",
				Headers: map[string]string{
					test.headerName: test.headerValue,
				},
			})

			// then:
			require.ErrorContains(t, err, strings.ToLower(test.headerName))
		})
	}
}

// TestConsumeReceivedCertificates tests the ConsumeReceivedCertificates method
func TestConsumeReceivedCertificates(t *testing.T) {
	// Set up dependencies
	mockWallet := wallet.NewTestWalletForRandomKey(t)
	mockSessionManager := NewMockSessionManager()
	requestedCerts := &utils.RequestedCertificateSet{}

	// Create AuthFetch instance
	authFetch := New(mockWallet, WithCertificatesToRequest(requestedCerts), WithSessionManager(mockSessionManager))

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
	authFetch := New(mockWallet, WithCertificatesToRequest(requestedCerts), WithSessionManager(mockSessionManager))

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

// TestAuthFetchConcurrentMapAccess tests for data races in concurrent map access
// Run with: go test -race -run TestAuthFetchConcurrentMapAccess
func TestAuthFetchConcurrentMapAccess(t *testing.T) {
	// Set up dependencies
	mockWallet := wallet.NewTestWalletForRandomKey(t)

	// Create AuthFetch instance
	authFetch := New(mockWallet)

	// Test concurrent access to peers map
	t.Run("concurrent peers map access", func(t *testing.T) {
		done := make(chan bool)
		const numGoroutines = 10

		// Spawn goroutines that read/write the peers map concurrently
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer func() { done <- true }()
				baseURL := fmt.Sprintf("https://example%d.com", id%3) // Use 3 URLs to force contention

				// Simulate the pattern from Fetch(): check if exists, then write
				for j := 0; j < 100; j++ {
					// Read operation (like line 227: if _, exists := a.peers[baseURL]; !exists)
					_ = authFetch.GetPeer(baseURL)

					// Write operation (like line 253: a.peers[baseURL] = peerToUse)
					authFetch.SetPeer(baseURL, &AuthPeer{
						IdentityKey: fmt.Sprintf("key-%d-%d", id, j),
					})

					// Another read (like line 371: a.peers[baseURL].IdentityKey)
					if peer := authFetch.GetPeer(baseURL); peer != nil {
						_ = peer.IdentityKey
					}
				}
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < numGoroutines; i++ {
			<-done
		}
	})

	// Test concurrent access to callbacks map
	t.Run("concurrent callbacks map access", func(t *testing.T) {
		done := make(chan bool)
		const numGoroutines = 10

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer func() { done <- true }()

				for j := 0; j < 100; j++ {
					key := fmt.Sprintf("nonce-%d-%d", id, j%5) // Use 5 keys to force contention

					// Write operation (like line 328)
					authFetch.SetCallback(key, func(resp interface{}) {}, func(err interface{}) {})

					// Read operation (like line 387)
					authFetch.GetCallback(key)

					// Delete operation (like line 389)
					authFetch.DeleteCallback(key)
				}
			}(i)
		}

		for i := 0; i < numGoroutines; i++ {
			<-done
		}
	})

	// Test concurrent access to certificatesReceived slice
	t.Run("concurrent certificatesReceived access", func(t *testing.T) {
		done := make(chan bool)
		const numGoroutines = 10

		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer func() { done <- true }()

				for j := 0; j < 100; j++ {
					// Append operation (like line 257)
					authFetch.AppendCertificatesReceived(&certificates.VerifiableCertificate{})

					// Read and clear operation (like ConsumeReceivedCertificates)
					_ = authFetch.ConsumeReceivedCertificates()
				}
			}(i)
		}

		for i := 0; i < numGoroutines; i++ {
			<-done
		}
	})
}
