package auth

import (
	"sync"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

// MockTransport is a fake transport implementation for testing
type MockTransport struct {
	messageHandler   func(message *AuthMessage) error
	sentMessages     []*AuthMessage
	sentMessagesChan chan *AuthMessage
	mu               sync.Mutex
	isPaired         bool
	pairedTransport  *MockTransport
}

func NewMockTransport() *MockTransport {
	return &MockTransport{
		sentMessages:     make([]*AuthMessage, 0),
		sentMessagesChan: make(chan *AuthMessage, 10),
	}
}

func (t *MockTransport) Send(message *AuthMessage) error {
	t.mu.Lock()
	t.sentMessages = append(t.sentMessages, message)
	t.mu.Unlock()

	t.sentMessagesChan <- message

	if t.isPaired && t.pairedTransport != nil && t.pairedTransport.messageHandler != nil {
		go func() {
			_ = t.pairedTransport.messageHandler(message)
		}()
	}
	return nil
}

func (t *MockTransport) OnData(callback func(message *AuthMessage) error) error {
	t.messageHandler = callback
	return nil
}

func (t *MockTransport) GetSentMessages() []*AuthMessage {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sentMessages
}

// PairTransports connects two transports so messages sent to one are received by the other
func PairTransports(transportA, transportB *MockTransport) {
	transportA.isPaired = true
	transportB.isPaired = true
	transportA.pairedTransport = transportB
	transportB.pairedTransport = transportA
}

// MockSessionManager for tests
type MockSessionManager struct {
	sessions map[string]*PeerSession
}

func NewMockSessionManager() *MockSessionManager {
	return &MockSessionManager{
		sessions: make(map[string]*PeerSession),
	}
}

// CreatePeerPair sets up two connected peers with their own wallets and transports
func CreatePeerPair(t *testing.T) (*Peer, *Peer, *utils.CompletedProtoWallet, *utils.CompletedProtoWallet) {
	// Create wallets and transports
	alicePk, err := ec.NewPrivateKey()
	require.NoError(t, err)
	aliceWallet, err := utils.NewCompletedProtoWallet(alicePk)
	require.NoError(t, err)
	bobPk, err := ec.NewPrivateKey()
	require.NoError(t, err)
	bobWallet, err := utils.NewCompletedProtoWallet(bobPk)
	require.NoError(t, err)

	aliceTransport := NewMockTransport()
	bobTransport := NewMockTransport()

	// Connect transports
	PairTransports(aliceTransport, bobTransport)

	// Create peers
	alice := NewPeer(&PeerOptions{
		Wallet:    aliceWallet,
		Transport: aliceTransport,
	})

	bob := NewPeer(&PeerOptions{
		Wallet:    bobWallet,
		Transport: bobTransport,
	})

	return alice, bob, aliceWallet, bobWallet
}

// TestPeerInitialization tests that a peer initializes correctly
func TestPeerInitialization(t *testing.T) {
	pk, err := ec.NewPrivateKey()
	require.NoError(t, err)
	wallet, err := utils.NewCompletedProtoWallet(pk)
	require.NoError(t, err)
	transport := NewMockTransport()

	// Test default initialization
	peer := NewPeer(&PeerOptions{
		Wallet:    wallet,
		Transport: transport,
	})

	require.NotNil(t, peer, "Peer should be created")
	require.Equal(t, wallet, peer.wallet, "Wallet should be set correctly")
	require.Equal(t, transport, peer.transport, "Transport should be set correctly")
	require.NotNil(t, peer.sessionManager, "SessionManager should be created")
	require.True(t, peer.autoPersistLastSession, "autoPersistLastSession should default to true")

	// Test with custom session manager and autoPersistLastSession=false
	sessionManager := NewSessionManager()
	autoPersist := false

	peer = NewPeer(&PeerOptions{
		Wallet:                 wallet,
		Transport:              transport,
		SessionManager:         sessionManager,
		AutoPersistLastSession: &autoPersist,
	})

	require.Equal(t, sessionManager, peer.sessionManager, "Custom SessionManager should be used")
	require.False(t, peer.autoPersistLastSession, "autoPersistLastSession should be false")
}

// TestPeerMessageExchange tests basic message exchange between peers
func TestPeerMessageExchange(t *testing.T) {
	alice, bob, _, bobWallet := CreatePeerPair(t)

	// Set up message reception for Bob
	messageReceived := make(chan []byte, 1)
	bob.ListenForGeneralMessages(func(senderPublicKey *ec.PublicKey, payload []byte) error {
		messageReceived <- payload
		return nil
	})

	// Alice sends a message to Bob
	testMessage := []byte("Hello Bob!")
	bobPubKey, err := bobWallet.GetPublicKey(t.Context(), wallet.GetPublicKeyArgs{IdentityKey: true}, "")
	require.NoError(t, err)
	err = alice.ToPeer(testMessage, bobPubKey.PublicKey, 5000)
	require.NoError(t, err, "Alice should send message successfully")

	// Wait for Bob to receive the message
	select {
	case receivedPayload := <-messageReceived:
		require.Equal(t, testMessage, receivedPayload, "Bob should receive Alice's message")
	case <-time.After(2 * time.Second):
		require.Fail(t, "Timed out waiting for Bob to receive message")
	}
}

// TestPeerCallbacks tests registering and unregistering callbacks
func TestPeerCallbacks(t *testing.T) {
	alice, _, _, _ := CreatePeerPair(t)

	// Test general message callbacks
	cb1 := func(senderPubKey *ec.PublicKey, payload []byte) error { return nil }
	cb2 := func(senderPubKey *ec.PublicKey, payload []byte) error { return nil }

	id1 := alice.ListenForGeneralMessages(cb1)
	id2 := alice.ListenForGeneralMessages(cb2)

	require.Len(t, alice.onGeneralMessageReceivedCallbacks, 2, "Should have two callbacks registered")

	alice.StopListeningForGeneralMessages(id1)
	require.Len(t, alice.onGeneralMessageReceivedCallbacks, 1, "Should have one callback after removal")

	alice.StopListeningForGeneralMessages(id2)
	require.Len(t, alice.onGeneralMessageReceivedCallbacks, 0, "Should have no callbacks after removal")

	// Test certificate callbacks
	certCb1 := func(senderPubKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error { return nil }
	certId1 := alice.ListenForCertificatesReceived(certCb1)

	require.Len(t, alice.onCertificateReceivedCallbacks, 1, "Should have one cert callback registered")

	alice.StopListeningForCertificatesReceived(certId1)
	require.Len(t, alice.onCertificateReceivedCallbacks, 0, "Should have no cert callbacks after removal")

	// Test certificate request callbacks
	reqCb1 := func(senderPubKey *ec.PublicKey, req utils.RequestedCertificateSet) error { return nil }
	reqId1 := alice.ListenForCertificatesRequested(reqCb1)

	require.Len(t, alice.onCertificateRequestReceivedCallbacks, 1, "Should have one cert request callback registered")

	alice.StopListeningForCertificatesRequested(reqId1)
	require.Len(t, alice.onCertificateRequestReceivedCallbacks, 0, "Should have no cert request callbacks after removal")
}

// TestPeerAuthentication tests the authentication flow between peers
func TestPeerAuthentication(t *testing.T) {
	// Skip this test for now as it requires a more complete mock implementation
	t.Skip("Skipping authentication test - requires full mock implementation")

	alice, bob, aliceWallet, bobWallet := CreatePeerPair(t)

	// Setup channels to track authentication completion
	aliceAuthenticated := make(chan bool, 1)
	bobAuthenticated := make(chan bool, 1)

	ctx := t.Context()

	// Track when authentication completes
	alice.ListenForGeneralMessages(func(senderPublicKey *ec.PublicKey, payload []byte) error {
		aliceAuthenticated <- true
		return nil
	})

	bob.ListenForGeneralMessages(func(senderPublicKey *ec.PublicKey, payload []byte) error {
		bobAuthenticated <- true
		return nil
	})

	// Alice sends message to Bob, which should trigger authentication
	go func() {
		err := alice.ToPeer([]byte("Hello Bob!"), nil, 5000)
		require.NoError(t, err)
	}()

	// Wait for authentication to complete
	select {
	case <-bobAuthenticated:
		// Authentication successful for Bob
	case <-time.After(2 * time.Second):
		require.Fail(t, "Timed out waiting for Bob's authentication")
	}

	// Bob replies to Alice
	go func() {
		// Get Alice's identity key
		alicePubKeyResult, _ := aliceWallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{IdentityKey: true}, "")

		err := bob.ToPeer([]byte("Hello Alice!"), alicePubKeyResult.PublicKey, 5000)
		require.NoError(t, err)
	}()

	// Wait for authentication to complete
	select {
	case <-aliceAuthenticated:
		// Authentication successful for Alice
	case <-time.After(2 * time.Second):
		require.Fail(t, "Timed out waiting for Alice's authentication")
	}

	// Verify that sessions were created
	alicePubKeyResult, _ := aliceWallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{IdentityKey: true}, "")
	bobPubKeyResult, _ := bobWallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{IdentityKey: true}, "")

	alicePubKeyStr := alicePubKeyResult.PublicKey.ToDERHex()
	bobPubKeyStr := bobPubKeyResult.PublicKey.ToDERHex()

	// Get Bob's session with Alice
	bobSession, err := bob.sessionManager.GetSession(alicePubKeyStr)
	require.NoError(t, err)
	require.NotNil(t, bobSession)
	require.True(t, bobSession.IsAuthenticated)

	// Get Alice's session with Bob
	aliceSession, err := alice.sessionManager.GetSession(bobPubKeyStr)
	require.NoError(t, err)
	require.NotNil(t, aliceSession)
	require.True(t, aliceSession.IsAuthenticated)

	// Test session reuse for another message
	err = alice.ToPeer([]byte("Another message"), bobPubKeyResult.PublicKey, 5000)
	require.NoError(t, err, "Should reuse existing session")
}

// TestPeerCertificateExchange tests certificate request and exchange
func TestPeerCertificateExchange(t *testing.T) {
	// Skip this test for now as it requires proper certificate handling
	t.Skip("Skipping certificate exchange test - requires complete certificate implementation")

	alice, bob, aliceWallet, bobWallet := CreatePeerPair(t)

	// Setup certificate tracking
	aliceCertReceived := make(chan bool, 1)
	bobCertReceived := make(chan bool, 1)

	alice.ListenForCertificatesReceived(func(senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
		aliceCertReceived <- true
		return nil
	})

	bob.ListenForCertificatesReceived(func(senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
		bobCertReceived <- true
		return nil
	})

	// Setup certificate requirements
	certType := "testCertType"
	requiredField := "testField"

	aliceCertReqs := utils.RequestedCertificateSet{
		Certifiers: []string{"any"},
		CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
			certType: []string{requiredField},
		},
	}

	bobCertReqs := utils.RequestedCertificateSet{
		Certifiers: []string{"any"},
		CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
			certType: []string{requiredField},
		},
	}

	// Set certificate requirements
	alice.CertificatesToRequest = aliceCertReqs
	bob.CertificatesToRequest = bobCertReqs

	// Mock certificates for both wallets
	aliceCert := &certificates.VerifiableCertificate{
		Certificate: certificates.Certificate{
			Type:         wallet.Base64String(certType),
			SerialNumber: "alice-serial-12345",
			Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{
				wallet.CertificateFieldNameUnder50Bytes(requiredField): wallet.Base64String("Alice's data"),
			},
		},
		Keyring: map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{},
	}

	bobCert := &certificates.VerifiableCertificate{
		Certificate: certificates.Certificate{
			Type:         wallet.Base64String(certType),
			SerialNumber: "bob-serial-67890",
			Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{
				wallet.CertificateFieldNameUnder50Bytes(requiredField): wallet.Base64String("Bob's data"),
			},
		},
		Keyring: map[wallet.CertificateFieldNameUnder50Bytes]wallet.Base64String{},
	}

	// Set mock certificates in the wallets
	aliceWallet.SetMockCertificates([]*certificates.VerifiableCertificate{aliceCert})
	bobWallet.SetMockCertificates([]*certificates.VerifiableCertificate{bobCert})

	// Alice and Bob exchange messages to trigger authentication and certificate exchange
	go func() {
		err := alice.ToPeer([]byte("Hello Bob!"), nil, 5000)
		require.NoError(t, err)
	}()

	// Wait for certificate exchange
	timeout := time.After(2 * time.Second)
	waitingForAlice, waitingForBob := true, true

	for waitingForAlice || waitingForBob {
		select {
		case <-aliceCertReceived:
			waitingForAlice = false
		case <-bobCertReceived:
			waitingForBob = false
		case <-timeout:
			if waitingForAlice {
				require.Fail(t, "Timed out waiting for Alice to receive cert")
			}
			if waitingForBob {
				require.Fail(t, "Timed out waiting for Bob to receive cert")
			}
			return
		}
	}

	// Verify manual certificate request
	alicePubKeyResult, _ := aliceWallet.GetPublicKey(t.Context(), wallet.GetPublicKeyArgs{IdentityKey: true}, "")
	// bobPubKeyResult, _ := bobWallet.GetPublicKey(wallet.GetPublicKeyArgs{IdentityKey: true}, "")

	// _ = bobPubKeyResult.PublicKey.ToDERHex()

	// Bob makes a specific certificate request to Alice
	customCertReqs := utils.RequestedCertificateSet{
		Certifiers: []string{"any"},
		CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
			"customType": []string{"customField"},
		},
	}

	err := bob.RequestCertificates(alicePubKeyResult.PublicKey, customCertReqs, 1000)
	require.NoError(t, err, "Should request certificates successfully")
}

// TestPeerSessionManagement tests session creation, retrieval, and timeout
func TestPeerSessionManagement(t *testing.T) {
	alice, bob, aliceWallet, bobWallet := CreatePeerPair(t)

	ctx := t.Context()

	// Use all variables to avoid linter errors
	require.NotNil(t, bob, "Bob peer should be created")

	// Verify we can create a session manually
	alicePubKeyResult, _ := aliceWallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{IdentityKey: true}, "")
	bobPubKeyResult, _ := bobWallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{IdentityKey: true}, "")

	alicePubKeyStr := alicePubKeyResult.PublicKey.ToDERHex()
	bobPubKeyStr := bobPubKeyResult.PublicKey.ToDERHex()

	t.Logf("Testing session with Alice's pubkey: %s", alicePubKeyStr)
	t.Logf("Testing session with Bob's pubkey: %s", bobPubKeyStr)

	// Create a session with a short timeout
	go func() {
		err := alice.ToPeer([]byte("Hello Bob!"), bobPubKeyResult.PublicKey, 100)
		require.NoError(t, err)
	}()

	// Wait a bit for the session to be created
	time.Sleep(500 * time.Millisecond)

	// Verify the session exists
	session, err := alice.sessionManager.GetSession(bobPubKeyStr)
	require.NoError(t, err)
	require.NotNil(t, session)
	require.True(t, session.IsAuthenticated)

	// Test automatic use of the last interacted peer
	err = alice.ToPeer([]byte("Using last peer"), nil, 100)
	require.NoError(t, err)
	require.Equal(t, bobPubKeyStr, alice.lastInteractedWithPeer.ToDERHex(), "Should track last interacted peer")
}

// TestPeerErrorHandling tests error handling in various scenarios
func TestPeerErrorHandling(t *testing.T) {
	// Skip for now and add a more targeted test
	t.Skip("Skip error handling tests until we have proper mock implementations")

	alice, _, aliceWallet, bobWallet := CreatePeerPair(t)

	// Use all variables to avoid linter errors
	require.NotNil(t, aliceWallet, "Alice wallet should be created")
	require.NotNil(t, bobWallet, "Bob wallet should be created")
	require.NotNil(t, alice, "Alice peer should be created")

	// Test timeout - use a very short timeout
	// Create a new transport that is not paired with anything
	unpairedTransport := NewMockTransport()

	// Create a new peer with the unpaired transport
	timeoutPeer := NewPeer(&PeerOptions{
		Wallet:    aliceWallet,
		Transport: unpairedTransport,
	})

	// This should time out because no one will respond
	err := timeoutPeer.ToPeer([]byte("Test timeout"), nil, 1) // 1ms timeout
	require.Error(t, err, "Should timeout during authentication")
}

// TestPeerBasics tests the very basic peer functionality that should always work
func TestPeerBasics(t *testing.T) {
	pk, err := ec.NewPrivateKey()
	require.NoError(t, err)
	wallet, err := utils.NewCompletedProtoWallet(pk)
	require.NoError(t, err)
	transport := NewMockTransport()

	// Test creating a peer
	peer := NewPeer(&PeerOptions{
		Wallet:    wallet,
		Transport: transport,
	})

	// Check that the peer was created with the correct properties
	require.NotNil(t, peer, "Peer should be created")
	require.Equal(t, wallet, peer.wallet, "Peer should use the provided wallet")
	require.Equal(t, transport, peer.transport, "Peer should use the provided transport")
	require.NotNil(t, peer.sessionManager, "Peer should have a session manager")
	require.True(t, peer.autoPersistLastSession, "Peer should default to auto-persist last session")

	// Test callback registration and removal
	cb := func(senderPublicKey *ec.PublicKey, payload []byte) error { return nil }
	id := peer.ListenForGeneralMessages(cb)
	require.Len(t, peer.onGeneralMessageReceivedCallbacks, 1, "Should have one callback registered")

	peer.StopListeningForGeneralMessages(id)
	require.Len(t, peer.onGeneralMessageReceivedCallbacks, 0, "Should have no callbacks after removal")
}
