package auth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/auth/transports"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	"github.com/bsv-blockchain/go-sdk/internal/logging"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/testcertificates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	alicePrivKeyHex     = "143ab18a84d3b25e1a13cefa90038411e5d2014590a2a4a57263d1593c8dee1c"
	bobPrivKeyHex       = "0881208859876fc227d71bfb8b91814462c5164b6fee27e614798f6e85d2547d"
	aliceName           = "Alice"
	bobName             = "Bob"
	contactCertTypeName = "contact"
	nameField           = "name"
	emailField          = "email"
)

var anyMessage = []byte("Any message")

// MockTransport is a fake transport implementation for testing
type MockTransport struct {
	// Name makes the debugging easier
	Name            string
	messageHandler  func(ctx context.Context, message *auth.AuthMessage) error
	pairedTransport *MockTransport
}

func NewMockTransport(name string) *MockTransport {
	return &MockTransport{
		Name: name,
	}
}

func (t *MockTransport) PairWith(transport *MockTransport) {
	if transport == nil {
		panic("invalid test setup: cannot pair with nil transport")
	}
	t.pairedTransport = transport
	transport.pairedTransport = t
}

func (t *MockTransport) Send(ctx context.Context, message *auth.AuthMessage) error {
	if t.messageHandler == nil {
		return fmt.Errorf("%s transport issue: %w", t.Name, transports.ErrNoHandlerRegistered)
	}

	if t.pairedTransport == nil {
		panic("invalid test setup: cannot send message without a paired transport")
	}

	err := t.pairedTransport.receive(ctx, message)
	if err != nil {
		return fmt.Errorf("%s received error on send to paired transport: %w", t.Name, err)
	}
	return nil
}

func (t *MockTransport) OnData(callback func(context.Context, *auth.AuthMessage) error) error {
	t.messageHandler = callback
	return nil
}

func (t *MockTransport) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	if t.messageHandler == nil {
		return nil, fmt.Errorf("no message handler registered")
	}

	return t.messageHandler, nil
}

func (t *MockTransport) String() string {
	if t.pairedTransport != nil {
		return fmt.Sprintf("Transport %s -> %s", t.Name, t.pairedTransport.Name)
	}
	return fmt.Sprintf("Transport %s -/-> nil", t.Name)
}

func (t *MockTransport) receive(ctx context.Context, message *auth.AuthMessage) error {
	if t.messageHandler != nil {
		return t.messageHandler(ctx, message)
	}
	return fmt.Errorf("%s transport issue: %w", t.Name, transports.ErrNoHandlerRegistered)
}

// LoggingMockTransport extends MockTransportOld with detailed logging
type LoggingMockTransport struct {
	*MockTransport
	logger *slog.Logger
}

func NewLoggingMockTransport(name string, logger *slog.Logger) *LoggingMockTransport {
	if logger == nil {
		logger = slog.Default()
	}

	return &LoggingMockTransport{
		MockTransport: NewMockTransport(name),
		logger:        logger.With(slog.String("service", "transport"), slog.String("actor", name)),
	}
}

func (t *LoggingMockTransport) Send(ctx context.Context, message *auth.AuthMessage) error {
	logger := t.logger.With(
		slog.String("direction", "SEND"),
		slog.String("messageType", string(message.MessageType)),
		slog.String("initialNonce", message.InitialNonce),
	)

	// Log specifics based on message type
	switch message.MessageType {
	case auth.MessageTypeInitialRequest:
		logger.InfoContext(ctx, "Initial Request", slog.String("nonce", message.InitialNonce))
		if len(message.RequestedCertificates.CertificateTypes) > 0 {
			logger.InfoContext(ctx, "Requiring Certificates from peer", slog.Group("requested", t.requestedCertificatesLoggingArgs(message)...))
		}
	case auth.MessageTypeInitialResponse:
		logger.InfoContext(ctx,
			"Initial Response",
			slog.String("nonce", message.Nonce),
			slog.String("yourNonce", message.YourNonce),
			slog.Int("received.certificates.count", len(message.Certificates)),
		)
		if len(message.Certificates) > 0 {
			logger.InfoContext(ctx, "Initial Response included certificates",
				slog.Group("received.certs", t.receivedCertificatesLoggingArgs(message)...),
			)
		}
	case auth.MessageTypeCertificateRequest:
		logger.InfoContext(ctx, "Certificate Request",
			slog.String("nonce", message.Nonce),
			slog.String("yourNonce", message.YourNonce),
			slog.Group("requested", t.requestedCertificatesLoggingArgs(message)...),
		)
	case auth.MessageTypeCertificateResponse:
		logger.InfoContext(ctx, "Certificate Response",
			slog.String("nonce", message.Nonce),
			slog.String("yourNonce", message.YourNonce),
			slog.Group("received.certs", t.receivedCertificatesLoggingArgs(message)...),
		)
	case auth.MessageTypeGeneral:
		logger.InfoContext(ctx, "General Message",
			slog.String("nonce", message.Nonce),
			slog.String("yourNonce", message.YourNonce),
		)
	}
	return t.MockTransport.Send(ctx, message)
}

func (t *LoggingMockTransport) OnData(callback func(context.Context, *auth.AuthMessage) error) error {
	wrappedCallback := func(ctx context.Context, message *auth.AuthMessage) error {
		t.logger.InfoContext(ctx, "Received message",
			slog.String("direction", "RECEIVE"),
			slog.String("messageType", string(message.MessageType)),
			slog.String("initialNonce", message.InitialNonce),
			slog.String("nonce", message.Nonce),
			slog.String("yourNonce", message.YourNonce),
			slog.String("identityKey", message.IdentityKey.ToDERHex()),
		)
		return callback(context.Background(), message)
	}
	return t.MockTransport.OnData(wrappedCallback)
}

func (t *LoggingMockTransport) receivedCertificatesLoggingArgs(message *auth.AuthMessage) []any {
	if len(message.Certificates) == 0 {
		return []any{
			slog.Int("count", 0),
		}
	}

	var args = make([]any, 0)
	for _, certificate := range message.Certificates {
		fields := fmt.Sprintf("%v", slices.Collect(maps.Keys(certificate.Fields)))

		var certType string
		certTypeArray, err := certificate.Type.ToArray()
		if err != nil {
			certType = string(certificate.Type)
		} else {
			certType = string(certTypeArray[:])
		}

		args = append(args, slog.Group(certType,
			slog.String("fields", fields),
			slog.String("certifier", certificate.Certifier.ToDERHex()),
		))
	}
	return args
}

func (t *LoggingMockTransport) requestedCertificatesLoggingArgs(message *auth.AuthMessage) []any {
	certificateRequestLoggingArgs := make([]any, 0)
	if len(message.RequestedCertificates.Certifiers) > 0 {
		certifiers := make([]string, 0)
		for _, certifier := range message.RequestedCertificates.Certifiers {
			certifiers = append(certifiers, certifier.ToDERHex())
		}
		certificateRequestLoggingArgs = append(certificateRequestLoggingArgs, slog.String("certifiers", fmt.Sprintf("%v", certifiers)))
	} else {
		certificateRequestLoggingArgs = append(certificateRequestLoggingArgs, slog.String("certifiers", "ANY"))
	}

	if len(message.RequestedCertificates.CertificateTypes) > 0 {
		certInfoLoggingArgs := make([]any, 0)
		for certType, certFields := range message.RequestedCertificates.CertificateTypes {
			certInfoLoggingArgs = append(certInfoLoggingArgs, slog.String(certType.String(), fmt.Sprintf("%v", certFields)))
		}

		certificateRequestLoggingArgs = append(certificateRequestLoggingArgs, slog.Group("certificates", certInfoLoggingArgs...))
	} else {
		certificateRequestLoggingArgs = append(certificateRequestLoggingArgs, slog.String("certificates", "NONE"))
	}
	return certificateRequestLoggingArgs
}

func (t *LoggingMockTransport) String() string {
	return fmt.Sprintf("Logging %s", t.MockTransport)
}

// Actor is a struct representing a counterparty in test scenarios.
// It is holding parts of the peer that can be used later for assertions.
type Actor struct {
	*auth.Peer

	// Name is for debugging simplification
	Name           string
	PrivKey        *ec.PrivateKey
	IdentityKey    *ec.PublicKey
	Transport      *MockTransport
	SessionManager auth.SessionManager
	Wallet         *wallet.TestWallet
}

func (a *Actor) ConnectWith(counterparty *Actor) {
	a.Transport.PairWith(counterparty.Transport)
}

// CreateActorsPair sets up two connected peers with their own wallets and transports
func CreateActorsPair(t testing.TB) (*Actor, *Actor) {
	alice := NewActor(t, aliceName, alicePrivKeyHex)
	bob := NewActor(t, bobName, bobPrivKeyHex)
	alice.ConnectWith(bob)

	return alice, bob
}

func NewActor(t testing.TB, name, privKeyHex string, opts ...func(options *auth.PeerOptions)) *Actor {
	privKey, err := ec.PrivateKeyFromHex(privKeyHex)
	require.NoErrorf(t, err, "invalid test setup: cannot restore %s's private key", name)

	peerWallet := wallet.NewTestWallet(t, privKey, wallet.WithTestWalletName(name))

	peerTransport := NewLoggingMockTransport(name, logging.NewTestLogger(t))

	sessionManger := auth.NewSessionManager()

	options := &auth.PeerOptions{
		Wallet:         peerWallet,
		Transport:      peerTransport,
		SessionManager: sessionManger,
	}

	for _, opt := range opts {
		opt(options)
	}

	peerInstance := auth.NewPeer(options)

	return &Actor{
		Name:           name,
		PrivKey:        privKey,
		IdentityKey:    privKey.PubKey(),
		Peer:           peerInstance,
		Transport:      peerTransport.MockTransport,
		Wallet:         peerWallet,
		SessionManager: sessionManger,
	}
}

func TestPeerAuthentication(t *testing.T) {
	// given:
	alice, bob := CreateActorsPair(t)

	// when:
	messageFromReceived := make(chan string, 1)
	bob.ListenForGeneralMessages(func(_ context.Context, senderPublicKey *ec.PublicKey, payload []byte) error {
		messageFromReceived <- senderPublicKey.ToDERHex()
		close(messageFromReceived)
		return nil
	})

	// and:
	err := alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000)
	require.NoError(t, err, "Alice should send message successfully")

	// then:
	select {
	case senderPublicKey := <-messageFromReceived:
		// Authentication successful for Alice
		require.Equal(t, alice.IdentityKey.ToDERHex(), senderPublicKey, "Bob should receive message from Alice")
	case <-time.After(500 * time.Millisecond):
		require.Fail(t, "Timed out waiting for Alice's authentication")
	}

	// Get Bob's session with Alice
	bobSession, err := bob.SessionManager.GetSession(alice.IdentityKey.ToDERHex())
	assert.NoError(t, err)
	if assert.NotNil(t, bobSession) {
		assert.True(t, bobSession.IsAuthenticated, "Bob should have an authenticated session with Alice")
	}

	// Get Alice's session with Bob
	aliceSession, err := alice.SessionManager.GetSession(bob.IdentityKey.ToDERHex())
	assert.NoError(t, err)
	if assert.NotNil(t, aliceSession) {
		assert.True(t, aliceSession.IsAuthenticated, "Alice should have an authenticated session with Bob")
	}
}

func TestPeerMessageExchange(t *testing.T) {
	// given:
	alice, bob := CreateActorsPair(t)

	// and:
	testMessage := []byte("Hello Bob!")

	// when: Set up message reception for Bob
	messageReceived := make(chan []byte, 1)
	bob.ListenForGeneralMessages(func(_ context.Context, senderPublicKey *ec.PublicKey, payload []byte) error {
		messageReceived <- payload
		close(messageReceived)
		return nil
	})

	// and: Alice sends a message to Bob
	err := alice.ToPeer(t.Context(), testMessage, bob.IdentityKey, 5000)
	require.NoError(t, err, "Alice should send message successfully")

	// then: Wait for Bob to receive the message
	select {
	case receivedPayload := <-messageReceived:
		require.Equal(t, testMessage, receivedPayload, "Bob should receive Alice's message")
	case <-time.After(500 * time.Millisecond):
		require.Fail(t, "Timed out waiting for Bob to receive message")
	}
}

func TestAuthenticationOfMultipleSenderPeerDevices(t *testing.T) {
	type ReceivedMessage struct {
		Device         string
		SenderIdentity string
		Payload        []byte
	}

	// given: multiple devices owned byt Alice
	alicePhone := NewActor(t, aliceName+"Phone", alicePrivKeyHex)
	aliceComputer := NewActor(t, aliceName+"Computer", alicePrivKeyHex)

	// and: ensure both devices has the same identity key
	aliceIdentityKey := alicePhone.IdentityKey.ToDERHex()
	require.Equal(t, aliceIdentityKey, aliceComputer.IdentityKey.ToDERHex(), "Invalid test setup: Alice's identity keys should be the same")

	// and: some devices owned by Bob
	bob := NewActor(t, bobName+"Phone", bobPrivKeyHex)

	// and: listen for received messages
	messageReceived := make(chan ReceivedMessage, 1)
	bob.ListenForGeneralMessages(func(_ context.Context, senderPublicKey *ec.PublicKey, payload []byte) error {
		messageReceived <- ReceivedMessage{
			Device:         bob.Name,
			SenderIdentity: senderPublicKey.ToDERHex(),
			Payload:        payload,
		}
		return nil
	})

	// and:
	phoneMessage := []byte("Hello from phone!")
	computerMessage := []byte("Hello from computer!")

	// when:
	alicePhone.ConnectWith(bob)

	// and:
	err := alicePhone.ToPeer(t.Context(), phoneMessage, bob.IdentityKey, 5000)
	require.NoError(t, err, "Alice should send message from phone successfully")

	// then: Wait for Bob to receive the message
	select {
	case receivedMessage := <-messageReceived:
		assert.Equal(t, phoneMessage, receivedMessage.Payload, "Bob should receive message from Alice's phone")
		assert.Equal(t, aliceIdentityKey, receivedMessage.SenderIdentity, "Bob should receive message from Alice's")
	case <-time.After(500 * time.Millisecond):
		require.Fail(t, "Timed out waiting for Bob to receive message")
	}

	// when:
	aliceComputer.ConnectWith(bob)

	// and:
	err = aliceComputer.ToPeer(t.Context(), computerMessage, bob.IdentityKey, 5000)
	require.NoError(t, err, "Alice should send message from computer successfully")

	// then: Wait again for Bob to receive the message
	select {
	case receivedMessage := <-messageReceived:
		assert.Equal(t, computerMessage, receivedMessage.Payload, "Bob should receive message from Alice's computer")
		assert.Equal(t, aliceIdentityKey, receivedMessage.SenderIdentity, "Bob should receive message from Alice's")
	case <-time.After(500 * time.Millisecond):
		require.Fail(t, "Timed out waiting for Bob to receive message")
	}
}

func TestAuthenticationOfMultipleReceiverPeerDevices(t *testing.T) {
	// FIXME: failing
	t.Skip("requests to multiple device is not working")

	type ReceivedMessage struct {
		Device         string
		SenderIdentity string
		Payload        []byte
	}

	// given: some device owned by Alice
	alice := NewActor(t, aliceName+"Phone", alicePrivKeyHex)

	// and:
	aliceIdentityKey := alice.IdentityKey.ToDERHex()

	// and: multiple devices owned by Bob
	bobPhone := NewActor(t, bobName+"Phone", bobPrivKeyHex)
	bobComputer := NewActor(t, bobName+"Computer", bobPrivKeyHex)

	// and: listen for received messages
	messageReceived := make(chan ReceivedMessage, 1)
	bobPhone.ListenForGeneralMessages(func(_ context.Context, senderPublicKey *ec.PublicKey, payload []byte) error {
		messageReceived <- ReceivedMessage{
			Device:         bobPhone.Name,
			SenderIdentity: senderPublicKey.ToDERHex(),
			Payload:        payload,
		}
		return nil
	})
	bobComputer.ListenForGeneralMessages(func(_ context.Context, senderPublicKey *ec.PublicKey, payload []byte) error {
		messageReceived <- ReceivedMessage{
			Device:         bobComputer.Name,
			SenderIdentity: senderPublicKey.ToDERHex(),
			Payload:        payload,
		}
		return nil
	})

	// and:
	phoneMessage := []byte("Hello phone!")
	computerMessage := []byte("Hello computer!")

	// when:
	alice.ConnectWith(bobPhone)

	// and:
	err := alice.ToPeer(t.Context(), phoneMessage, bobPhone.IdentityKey, 5000)
	require.NoError(t, err, "Alice should send message to Bob's phone successfully")

	// then: Wait for Bob to receive the message
	select {
	case receivedMessage := <-messageReceived:
		assert.Equal(t, bobPhone.Name, receivedMessage.Device, "Expects concrete device received message from Alice")
		assert.Equal(t, phoneMessage, receivedMessage.Payload, "Expects concrete message from Alice's")
		assert.Equal(t, aliceIdentityKey, receivedMessage.SenderIdentity, "Bob should receive message from Alice's")
	case <-time.After(500 * time.Millisecond):
		require.Fail(t, "Timed out waiting for Bob to receive message")
	}

	// when:
	alice.ConnectWith(bobComputer)

	// and:
	err = alice.ToPeer(t.Context(), computerMessage, bobPhone.IdentityKey, 5000)
	require.NoError(t, err, "Alice should send message to Bob's computer successfully")

	// then: Wait again for Bob to receive the message
	select {
	case receivedMessage := <-messageReceived:
		assert.Equal(t, bobComputer.Name, receivedMessage.Device, "Expects concrete device received message from Alice")
		assert.Equal(t, computerMessage, receivedMessage.Payload, "Expects concrete message from Alice's")
		assert.Equal(t, aliceIdentityKey, receivedMessage.SenderIdentity, "Bob should receive message from Alice's")
	case <-time.After(500 * time.Millisecond):
		require.Fail(t, "Timed out waiting for Bob to receive message")
	}
}

func TestAuthenticationWithCertificatesRequestedBySender(t *testing.T) {
	// given:
	alice, bob := CreateActorsPair(t)

	// and: Bob (receiver) has some certificate
	bobCertManager := testcertificates.NewManager(t, bob.Wallet)

	bobsCert := bobCertManager.CertificateForTest().WithType(contactCertTypeName).
		WithFieldValue(emailField, bobName+"@example.com").
		Issue()

	// and: listen for a received message
	messageReceived := make(chan struct{}, 1)
	bob.ListenForGeneralMessages(func(_ context.Context, senderPublicKey *ec.PublicKey, payload []byte) error {
		messageReceived <- struct{}{}
		close(messageReceived)
		return nil
	})

	// when: Alice (sender) request certificates from counterparties
	alice.CertificatesToRequest = &utils.RequestedCertificateSet{
		Certifiers: []*ec.PublicKey{bobsCert.WalletCert.Certifier},
		CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
			bobsCert.WalletCert.Type: []string{emailField},
		},
	}

	// and:
	err := alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000)

	// then:
	require.NoError(t, err, "Alice should send message successfully")

	// and: Bob should receive message - because Alice accepts his certificates
	select {
	case <-messageReceived:
	case <-time.After(500 * time.Millisecond):
		require.Fail(t, "Timed out waiting for Alice's authentication")
	}
}

func TestAuthenticationWithCertificatesRequestedByReceiver(t *testing.T) {
	// given:
	alice, bob := CreateActorsPair(t)

	// and: Alice (sender) has some certificate
	aliceCertManager := testcertificates.NewManager(t, alice.Wallet)

	aliceCert := aliceCertManager.CertificateForTest().WithType(contactCertTypeName).
		WithFieldValue(emailField, aliceName+"@example.com").
		Issue()

	// and: listen for a received message
	messageReceived := make(chan struct{}, 1)
	bob.ListenForGeneralMessages(func(_ context.Context, senderPublicKey *ec.PublicKey, payload []byte) error {
		messageReceived <- struct{}{}
		close(messageReceived)
		return nil
	})

	// when: Bob (receiver) request certificates from counterparties
	bob.CertificatesToRequest = &utils.RequestedCertificateSet{
		Certifiers: []*ec.PublicKey{aliceCert.WalletCert.Certifier},
		CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
			aliceCert.WalletCert.Type: []string{emailField},
		},
	}

	// and:
	err := alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000)

	// then:
	require.NoError(t, err, "Alice should send message successfully")

	// and: bob should receive message - because Bob accepts Alice certificates
	select {
	case <-messageReceived:
	case <-time.After(500 * time.Millisecond):
		require.Fail(t, "Timed out waiting for Alice's authentication")
	}
}

func TestAuthenticationWithCertificatesReceivedListenerOnReceiverSide(t *testing.T) {
	// given:
	alice, bob := CreateActorsPair(t)

	// and: Alice (sender) has some certificate
	aliceCertManager := testcertificates.NewManager(t, alice.Wallet)

	aliceCert := aliceCertManager.CertificateForTest().WithType(contactCertTypeName).
		WithFieldValue(emailField, bobName+"@example.com").
		Issue()

	// and: Alice's wallet will prove that cert
	//    	this mocking is needed, because by default wallet is returning error when the
	//   	required field is missing.
	keyring := make(map[string]string)
	for key, value := range aliceCert.ToVerifiableCertificate(bob.IdentityKey).Keyring {
		keyring[string(key)] = string(value)
	}
	alice.Wallet.OnProveCertificate().ReturnSuccess(&wallet.ProveCertificateResult{
		KeyringForVerifier: keyring,
	})

	// and: listen for a received message
	messageReceived := make(chan struct{}, 1)
	bob.ListenForGeneralMessages(func(_ context.Context, senderPublicKey *ec.PublicKey, payload []byte) error {
		messageReceived <- struct{}{}
		close(messageReceived)
		return nil
	})

	// when: Bob (receiver) requests email and name from counterparties
	bob.CertificatesToRequest = &utils.RequestedCertificateSet{
		Certifiers: []*ec.PublicKey{aliceCert.WalletCert.Certifier},
		CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
			aliceCert.WalletCert.Type: []string{emailField, nameField},
		},
	}

	// and: Bob (receiver) treats only email field in certificate as required
	var certificatesReceivedListenerCalled bool
	bob.ListenForCertificatesReceived(func(_ context.Context, senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
		certificatesReceivedListenerCalled = true
		logger := logging.NewTestLogger(t).With(slog.String("service", "ListenForCertificatesReceived"), slog.String("actor", "Bob"))

		logger.Info("Handling received certificates with custom logic")
		for _, cert := range certs {
			if _, ok := cert.Fields[emailField]; ok {
				logger.Info("Accepting certificate with email field")
				return nil
			}
		}
		logger.Error("Requires email field in certificate, but didn't get it")
		return fmt.Errorf("requires email field in certificate")
	})

	// and:
	err := alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000)

	// then:
	require.NoError(t, err, "Alice should send message successfully")

	// and: bob should receive message - because Bob accepts Alice certificates
	select {
	case <-messageReceived:
	case <-time.After(500 * time.Millisecond):
		require.Fail(t, "Timed out waiting for Alice's authentication")
	}

	require.True(t, certificatesReceivedListenerCalled, "Bob's certificates received listener must be called")
}

func TestAuthenticationWithCertificatesReceivedListenerOnSenderSide(t *testing.T) {
	// given:
	alice, bob := CreateActorsPair(t)

	// and: Bob (receiver) has some certificate
	bobCertManager := testcertificates.NewManager(t, bob.Wallet)

	bobsCert := bobCertManager.CertificateForTest().WithType(contactCertTypeName).
		WithFieldValue(emailField, aliceName+"@example.com").
		Issue()

	// and: Bob's wallet will prove that cert
	//    	this mocking is needed, because by default wallet is returning error when the
	//   	 required field is missing
	keyring := make(map[string]string)
	for key, value := range bobsCert.ToVerifiableCertificate(alice.IdentityKey).Keyring {
		keyring[string(key)] = string(value)
	}
	bob.Wallet.OnProveCertificate().ReturnSuccess(&wallet.ProveCertificateResult{
		KeyringForVerifier: keyring,
	})

	// and: listen for a received message
	messageReceived := make(chan struct{}, 1)
	bob.ListenForGeneralMessages(func(_ context.Context, senderPublicKey *ec.PublicKey, payload []byte) error {
		messageReceived <- struct{}{}
		close(messageReceived)
		return nil
	})

	// when: Alice (sender) request certificates from counterparties
	alice.CertificatesToRequest = &utils.RequestedCertificateSet{
		Certifiers: []*ec.PublicKey{bobsCert.WalletCert.Certifier},
		CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
			bobsCert.WalletCert.Type: []string{emailField, nameField},
		},
	}

	// and: Alice (sender) treats only email field in certificate as required
	var certificatesReceivedListenerCalled bool
	alice.ListenForCertificatesReceived(func(_ context.Context, senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
		certificatesReceivedListenerCalled = true
		logger := logging.NewTestLogger(t).With(slog.String("service", "ListenForCertificatesReceived"), slog.String("actor", "Alice"))

		logger.Info("Handling received certificates with custom logic")
		for _, cert := range certs {
			if _, ok := cert.Fields[emailField]; ok {
				logger.Info("Accepting certificate with email field")
				return nil
			}
		}
		logger.Error("Requires email field in certificate, but didn't get it")
		return fmt.Errorf("requires email field in certificate")
	})

	// and:
	err := alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000)

	// then:
	require.NoError(t, err, "Alice should send message successfully")

	// and: bob should receive message - because Alice accepts his certificates
	select {
	case <-messageReceived:
	case <-time.After(500 * time.Millisecond):
		require.Fail(t, "Timed out waiting for Alice's authentication")
	}

	require.True(t, certificatesReceivedListenerCalled, "Bob's certificates received listener must be called")
}

func TestAuthenticationWithCertificatesFromCustomCertificatesRequestedCallbackOnReceiverSide(t *testing.T) {
	// given:
	alice, bob := CreateActorsPair(t)

	// and: Bob shouldn't try to get certificates from wallet
	bob.Wallet.OnListCertificates().ReturnError(fmt.Errorf("unexpected call to wallet.ListCertificates"))

	// and: Bob will setup custom certificates requested callback
	bob.ListenForCertificatesRequested(func(_ context.Context, senderPublicKey *ec.PublicKey, requestedCertificates utils.RequestedCertificateSet) error {
		var cert certificates.VerifiableCertificate
		// Use a verifiable certificate, that was working with TypeScript version
		err := json.Unmarshal([]byte(`{
										"type": "Y29udGFjdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
										"serialNumber": "Aw5m3amn/N/kbNCGtvc1sW9ijxw9bMsqITBrJ/PRdPw=",
										"subject": "0291354a19e9e81abe813b78a2055ce3d6d88c4dba4db22f365b743c2651ed3893",
										"certifier": "0331f9c94199a73ad4e372a831328e124d2da35d1d02369bbb67c78416ffe45d9a",
										"revocationOutpoint": "0000000000000000000000000000000000000000000000000000000000000000.0",
										"fields": {
										  "email": "VN8K/y5BQUUVRmIPEQLnSiUgzBXfKnGC/b4JuLvwryyZUCvN27H87oXEnWCl1d9EQ/EOQugj2mz0hEUh9Jcx"
										},
										"signature": "304402201b31b9802ddff295d17fadb8ffd18fc6aa518a858129e9b83c0ed8894d4dad120220606eeff756e917bf4783d779865b8ac21eb384c94826fb104cfc6eeabf5b0bc0",
										"keyring": {
										  "email": "WbcCm8nRS3sL3adCPxDQVom1s37kNzsgUpPQkepd+yGCj/yWnPYzme/93OoNhuRwLzk2qzOtwJLbQTEIa5m2zmuG/Qb3pHVX7/ijocqc0Zk="
										}
									  }`),
			&cert)
		if err != nil {
			return fmt.Errorf("cannot recreate verifiable certificate from json, %w", err)
		}
		return bob.SendCertificateResponse(t.Context(), senderPublicKey, []*certificates.VerifiableCertificate{&cert})
	})

	// and: listen for a received message
	messageReceived := make(chan struct{}, 1)
	bob.ListenForGeneralMessages(func(_ context.Context, senderPublicKey *ec.PublicKey, payload []byte) error {
		messageReceived <- struct{}{}
		close(messageReceived)
		return nil
	})

	// when: Alice (sender) request certificates from counterparties
	certType, err := wallet.CertificateTypeFromString(contactCertTypeName)
	require.NoError(t, err)

	alice.CertificatesToRequest = &utils.RequestedCertificateSet{
		CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
			certType: []string{emailField},
		},
	}

	// and:
	err = alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000)

	// then:
	require.NoError(t, err, "Alice should send message successfully")

	// and: bob should receive message - because Alice accepts his certificates
	select {
	case <-messageReceived:
	case <-time.After(500 * time.Millisecond):
		require.Fail(t, "Timed out waiting for Alice's authentication")
	}
}

func TestAuthenticationWithCertificatesFromCustomCertificatesRequestedCallbackOnSenderSide(t *testing.T) {
	// given:
	alice, bob := CreateActorsPair(t)

	// and: listen for a received message
	messageReceived := make(chan struct{}, 1)
	bob.ListenForGeneralMessages(func(_ context.Context, senderPublicKey *ec.PublicKey, payload []byte) error {
		messageReceived <- struct{}{}
		close(messageReceived)
		return nil
	})

	// and: Alice will setup custom certificates requested callback
	alice.ListenForCertificatesRequested(func(_ context.Context, senderPublicKey *ec.PublicKey, requestedCertificates utils.RequestedCertificateSet) error {
		var cert certificates.VerifiableCertificate
		// Use a verifiable certificate, that was working with TypeScript version
		err := json.Unmarshal([]byte(`{
										  "type": "Y29udGFjdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
										  "serialNumber": "94W2cOmyZ/cyHu1DwkKMltfBN2KxAKwMgEo9bKt6Mg8=",
										  "subject": "0320bbfb879bbd6761ecd2962badbb41ba9d60ca88327d78b07ae7141af6b6c810",
										  "certifier": "0331f9c94199a73ad4e372a831328e124d2da35d1d02369bbb67c78416ffe45d9a",
										  "revocationOutpoint": "0000000000000000000000000000000000000000000000000000000000000000.0",
										  "fields": {
											"email": "AmceSxxZI5kIjMDM3lPWxjBIEkgYWMeeS+2/X7bVdDN+T7JkZJRt+qM2PSRDAlM8u52V7GMMA3pJKsQcMNdaDrQ="
										  },
										  "signature": "3045022100f02ba34d24eeccf982a2e437dc25c5db3e940c81d0274f7e4b4451e590222f6c02207de700f2a70d09c9cc52acb9818e24a5c1e0abe270149312bf2bf5ce38ca1532",
										  "keyring": {
											"email": "ShGz03zETbeVGmvrXMo1kV6Q4+wWJrMQfeJJbl5QTPaYMKO42TXeIoAYk3QZmwBA8lz3LPjE5ZEHr7rQLC/w1YkRSHdOBdm0XRVal0SG+iw="
										  }
										}`),
			&cert)
		if err != nil {
			return fmt.Errorf("cannot recreate verifiable certificate from json, %w", err)
		}
		return alice.SendCertificateResponse(t.Context(), senderPublicKey, []*certificates.VerifiableCertificate{&cert})
	})

	// and: Alice shouldn't try to get certificates from wallet
	alice.Wallet.OnListCertificates().ReturnError(fmt.Errorf("unexpected call to wallet.ListCertificates"))

	// when: Bob (receiver) request certificates from counterparties
	certType, err := wallet.CertificateTypeFromString(contactCertTypeName)
	require.NoError(t, err)

	bob.CertificatesToRequest = &utils.RequestedCertificateSet{
		CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
			certType: []string{emailField},
		},
	}

	// and:
	err = alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000)

	// then:
	require.NoError(t, err, "Alice should send message successfully")

	// and: bob should receive message - because Bob accepts Alice certificates
	select {
	case <-messageReceived:
	case <-time.After(500 * time.Millisecond):
		require.Fail(t, "Timed out waiting for Alice's authentication")
	}
}

func TestCertificateExchange(t *testing.T) {
	// given:
	alice, bob := CreateActorsPair(t)

	// and: Bob (receiver) has some certificate
	bobCertManager := testcertificates.NewManager(t, bob.Wallet)

	bobsCert := bobCertManager.CertificateForTest().WithType(contactCertTypeName).
		WithFieldValue(emailField, aliceName+"@example.com").
		Issue()

	// and: Alice listen for a received certificates
	var certificatesReceivedListenerCalled bool
	alice.ListenForCertificatesReceived(func(_ context.Context, senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
		certificatesReceivedListenerCalled = true
		logger := logging.NewTestLogger(t).With(slog.String("service", "ListenForCertificatesReceived"), slog.String("actor", "Alice"))

		logger.Info("Handling received certificates with custom logic")
		for _, cert := range certs {
			if _, ok := cert.Fields[emailField]; ok {
				logger.Info("Accepting certificate with email field")
				return nil
			}
		}
		logger.Error("Requires email field in certificate, but didn't get it")
		return fmt.Errorf("requires email field in certificate")
	})

	// when: Alice (sender) requests certificates from counterparties
	err := alice.RequestCertificates(t.Context(), bob.IdentityKey, utils.RequestedCertificateSet{
		Certifiers: []*ec.PublicKey{bobsCert.WalletCert.Certifier},
		CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
			bobsCert.WalletCert.Type: []string{emailField},
		},
	}, 5000)

	// then:
	require.NoError(t, err, "Alice should send request successfully")

	require.True(t, certificatesReceivedListenerCalled, "Alice's certificates received listener must be called")
}

func TestCertificateExchangeWithCustomFlow(t *testing.T) {
	// given:
	alice, bob := CreateActorsPair(t)

	// and:
	const libraryCardTypeName = "libraryCard"
	const ownerField = "owner"
	messageWithBook := []byte("Here is your book!")

	// and:
	certType, err := wallet.CertificateTypeFromString(libraryCardTypeName)
	require.NoError(t, err, "invalid test setup, cannot create cert type from string")

	// and: Alice has a library card issued
	aliceCertManager := testcertificates.NewManager(t, alice.Wallet)

	aliceCertManager.CertificateForTest().WithType(libraryCardTypeName).
		WithFieldValue(ownerField, aliceName).
		IssueWithCertifier(bob.PrivKey)

	// and: Alice will listen for receiving the book
	messageReceived := make(chan []byte, 1)
	alice.ListenForGeneralMessages(func(_ context.Context, senderPublicKey *ec.PublicKey, payload []byte) error {
		messageReceived <- payload
		close(messageReceived)
		return nil
	})

	// when: Bob receives message about book, he requires sender to give him a library card
	certReceived := make(chan struct{}, 1)
	bob.ListenForGeneralMessages(func(_ context.Context, senderPublicKey *ec.PublicKey, payload []byte) error {

		// Bob will make a dedicated request for certificates
		err := bob.RequestCertificates(t.Context(), senderPublicKey, utils.RequestedCertificateSet{
			Certifiers: []*ec.PublicKey{bob.IdentityKey},
			CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
				certType: []string{ownerField},
			},
		}, 500)
		if err != nil {
			return fmt.Errorf("failed to request for library card from requester, %w", err)
		}

		// Then he will wait for receiving certificates
		select {
		case <-certReceived:
		case <-time.After(500 * time.Millisecond):
			require.Fail(t, "Timed out waiting for Alice's to give her a library card")
		}

		//  Bob received certificate with library card, so now he can give the book to Alice.
		err = bob.ToPeer(t.Context(), messageWithBook, senderPublicKey, 5000)
		if err != nil {
			return fmt.Errorf("failed to give book to Alice: %w", err)
		}
		return nil
	})

	// and: Bob
	bob.ListenForCertificatesReceived(func(_ context.Context, senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
		// We're expecting to receive library card only.
		assert.Len(t, certs, 1, "Bob should receive a library card only")
		assert.EqualValues(t, certType.Base64(), certs[0].Type, "Bob should receive cert of type library card")
		assert.Equal(t, *bob.IdentityKey, certs[0].Certifier, "Bob should be a certifier of the library card")
		assert.Contains(t, certs[0].Fields, wallet.CertificateFieldNameUnder50Bytes(ownerField), "Library card cert should have owner field")

		certReceived <- struct{}{}
		close(certReceived)
		return nil
	})

	// and: Alice came to library and asked for book.
	err = alice.ToPeer(t.Context(), []byte("Gimme book!"), bob.IdentityKey, 5000)

	// then:
	require.NoError(t, err, "Alice should send message successfully")

	// and: Alice should receive the book
	select {
	case messageToAlice := <-messageReceived:
		assert.Equal(t, messageWithBook, messageToAlice)
	case <-time.After(500 * time.Millisecond):
		require.Fail(t, "Timed out waiting for Alice's authentication")
	}
}

func TestCertificatesRejectedByReceiver(t *testing.T) {
	errorCases := map[string]struct {
		makeInvalid          func(*certificates.VerifiableCertificate) *certificates.VerifiableCertificate
		customValidationFail bool
	}{
		"not signed certificate": {
			makeInvalid: func(certificate *certificates.VerifiableCertificate) *certificates.VerifiableCertificate {
				certificate.Signature = util.ByteString("")
				return certificate
			},
		},
		"signature not match data": {
			makeInvalid: func(certificate *certificates.VerifiableCertificate) *certificates.VerifiableCertificate {
				certificate.RevocationOutpoint = &transaction.Outpoint{Index: 1}
				return certificate
			},
		},
		"field cannot be decrypted": {
			makeInvalid: func(certificate *certificates.VerifiableCertificate) *certificates.VerifiableCertificate {
				certificate.Keyring[emailField] = wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("invalid_key")))
				return certificate
			},
		},
		"custom validation returns error": {
			makeInvalid: func(certificate *certificates.VerifiableCertificate) *certificates.VerifiableCertificate {
				return certificate
			},
			customValidationFail: true,
		},
	}
	for name, test := range errorCases {
		t.Run(name, func(t *testing.T) {
			// given:
			alice, bob := CreateActorsPair(t)

			// and: Alice has some certificate
			aliceCertManager := testcertificates.NewManager(t, alice.Wallet, testcertificates.WithSkipAssignToSubjectWallet())

			aliceCert := aliceCertManager.CertificateForTest().WithType(contactCertTypeName).
				WithFieldValue(emailField, aliceName+"@example.com").
				Issue()

			verifiableCert := aliceCert.ToVerifiableCertificate(bob.IdentityKey)

			// and: alice will send invalid certificate
			invalidCertificate := test.makeInvalid(verifiableCert)

			alice.ListenForCertificatesRequested(func(_ context.Context, senderPublicKey *ec.PublicKey, requestedCertificates utils.RequestedCertificateSet) error {
				err := alice.SendCertificateResponse(t.Context(), senderPublicKey, []*certificates.VerifiableCertificate{invalidCertificate})
				if err != nil {
					return fmt.Errorf("failed to send certificates to counterparty, %w", err)
				}
				return nil
			})

			// and: listen for a received message
			bob.ListenForGeneralMessages(func(_ context.Context, senderPublicKey *ec.PublicKey, payload []byte) error {
				assert.Fail(t, "Bob should not receive a general messsage")
				return nil
			})

			// when: Bob (receiver) request certificates from counterparties
			bob.CertificatesToRequest = &utils.RequestedCertificateSet{
				Certifiers: []*ec.PublicKey{aliceCert.WalletCert.Certifier},
				CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
					aliceCert.WalletCert.Type: []string{emailField},
				},
			}

			// and: applies custom validation on received certificates
			bob.ListenForCertificatesReceived(func(_ context.Context, senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
				if test.customValidationFail {
					return fmt.Errorf("custom validation error")
				}
				return nil
			})

			// and:
			err := alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000)

			// then:
			require.Error(t, err, "Alice certificates should be rejected: thanks to mock transport Alice should get info about rejected certificate")
		})
	}
}

func TestCertificatesRejectedBySender(t *testing.T) {
	errorCases := map[string]struct {
		makeInvalid          func(*certificates.VerifiableCertificate) *certificates.VerifiableCertificate
		customValidationFail bool
	}{
		"not signed certificate": {
			makeInvalid: func(certificate *certificates.VerifiableCertificate) *certificates.VerifiableCertificate {
				certificate.Signature = util.ByteString("")
				return certificate
			},
		},
		"signature not match data": {
			makeInvalid: func(certificate *certificates.VerifiableCertificate) *certificates.VerifiableCertificate {
				certificate.RevocationOutpoint = &transaction.Outpoint{Index: 1}
				return certificate
			},
		},
		"field cannot be decrypted": {
			makeInvalid: func(certificate *certificates.VerifiableCertificate) *certificates.VerifiableCertificate {
				certificate.Keyring[emailField] = wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("invalid_key")))
				return certificate
			},
		},
		"custom validation returns error": {
			makeInvalid: func(certificate *certificates.VerifiableCertificate) *certificates.VerifiableCertificate {
				return certificate
			},
			customValidationFail: true,
		},
	}
	for name, test := range errorCases {
		t.Run(name, func(t *testing.T) {
			// given:
			alice, bob := CreateActorsPair(t)

			// and: Bob (receiver) has some certificate
			bobCertManager := testcertificates.NewManager(t, bob.Wallet, testcertificates.WithSkipAssignToSubjectWallet())

			bobsCert := bobCertManager.CertificateForTest().WithType(contactCertTypeName).
				WithFieldValue(emailField, aliceName+"@example.com").
				Issue()

			verifiableCert := bobsCert.ToVerifiableCertificate(alice.IdentityKey)

			// and: Bob will send invalid certificate
			invalidCertificate := test.makeInvalid(verifiableCert)

			bob.ListenForCertificatesRequested(func(_ context.Context, senderPublicKey *ec.PublicKey, requestedCertificates utils.RequestedCertificateSet) error {
				err := bob.SendCertificateResponse(t.Context(), senderPublicKey, []*certificates.VerifiableCertificate{invalidCertificate})
				if err != nil {
					return fmt.Errorf("failed to send certificates to counterparty, %w", err)
				}
				return nil
			})

			// and: listen for a received message
			bob.ListenForGeneralMessages(func(_ context.Context, senderPublicKey *ec.PublicKey, payload []byte) error {
				assert.Fail(t, "Bob should not receive a general messsage")
				return nil
			})

			// when: Alice (sender) request certificates from counterparties
			alice.CertificatesToRequest = &utils.RequestedCertificateSet{
				Certifiers: []*ec.PublicKey{bobsCert.WalletCert.Certifier},
				CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
					bobsCert.WalletCert.Type: []string{emailField},
				},
			}

			// and: applies custom validation on received certificates
			alice.ListenForCertificatesReceived(func(_ context.Context, senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
				if test.customValidationFail {
					return fmt.Errorf("custom validation error")
				}
				return nil
			})

			// and:
			err := alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000)

			// then:
			require.Error(t, err, "Bob's certificates should be rejected: thanks to mock transport we get info about rejected certificate")
		})
	}
}

func TestCustomRequestedCertificatesRejected(t *testing.T) {
	errorCases := map[string]struct {
		makeInvalid          func(*certificates.VerifiableCertificate) *certificates.VerifiableCertificate
		customValidationFail bool
	}{
		"not signed certificate": {
			makeInvalid: func(certificate *certificates.VerifiableCertificate) *certificates.VerifiableCertificate {
				certificate.Signature = util.ByteString("")
				return certificate
			},
		},
		"signature not match data": {
			makeInvalid: func(certificate *certificates.VerifiableCertificate) *certificates.VerifiableCertificate {
				certificate.RevocationOutpoint = &transaction.Outpoint{Index: 1}
				return certificate
			},
		},
		"field cannot be decrypted": {
			makeInvalid: func(certificate *certificates.VerifiableCertificate) *certificates.VerifiableCertificate {
				certificate.Keyring[emailField] = wallet.StringBase64(base64.StdEncoding.EncodeToString([]byte("invalid_key")))
				return certificate
			},
		},
		"custom validation returns error": {
			makeInvalid: func(certificate *certificates.VerifiableCertificate) *certificates.VerifiableCertificate {
				return certificate
			},
			customValidationFail: true,
		},
	}
	for name, test := range errorCases {
		t.Run(name, func(t *testing.T) {
			// given:
			alice, bob := CreateActorsPair(t)

			// and: Bob (receiver) has some certificate
			bobCertManager := testcertificates.NewManager(t, bob.Wallet, testcertificates.WithSkipAssignToSubjectWallet())

			bobsCert := bobCertManager.CertificateForTest().WithType(contactCertTypeName).
				WithFieldValue(emailField, aliceName+"@example.com").
				Issue()

			verifiableCert := bobsCert.ToVerifiableCertificate(alice.IdentityKey)

			// and: Bob will send invalid certificate
			invalidCertificate := test.makeInvalid(verifiableCert)

			bob.ListenForCertificatesRequested(func(_ context.Context, senderPublicKey *ec.PublicKey, requestedCertificates utils.RequestedCertificateSet) error {
				err := bob.SendCertificateResponse(t.Context(), senderPublicKey, []*certificates.VerifiableCertificate{invalidCertificate})
				if err != nil {
					return fmt.Errorf("failed to send certificates to counterparty, %w", err)
				}
				return nil
			})

			// when: applies custom validation on received certificates
			alice.ListenForCertificatesReceived(func(_ context.Context, senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
				if test.customValidationFail {
					return fmt.Errorf("custom validation error")
				}
				return nil
			})

			// and: Alice (sender) request certificates from counterparties
			err := alice.RequestCertificates(t.Context(), bob.IdentityKey, utils.RequestedCertificateSet{
				Certifiers: []*ec.PublicKey{bobsCert.WalletCert.Certifier},
				CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
					bobsCert.WalletCert.Type: []string{emailField},
				},
			}, 5000)

			// then:
			require.Error(t, err, "Bob's certificates should be rejected: thanks to mock transport we get info about rejected certificate")
		})
	}
}

func TestPeerCallbacksRegistrationAndUnregistration(t *testing.T) {
	t.Run("ListenForGeneralMessages", func(t *testing.T) {
		// given:
		alice, bob := CreateActorsPair(t)

		// when: callback registered
		var numberOfCalls int
		callbackID := bob.ListenForGeneralMessages(func(_ context.Context, senderPublicKey *ec.PublicKey, payload []byte) error {
			numberOfCalls++
			return nil
		})

		// and: alice sends a message
		err := alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000)
		require.NoError(t, err, "communication with listener failed")

		// then:
		require.Equal(t, 1, numberOfCalls, "Callback should have been called")

		// when: callback unregistered
		bob.StopListeningForGeneralMessages(callbackID)

		// and: alice sends a message
		err = alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000)
		require.NoError(t, err, "communication after stop listening failed")

		// then:
		require.Equal(t, 1, numberOfCalls, "Only one callback should have been registered")
	})

	t.Run("ListenForCertificatesReceived - on message handling", func(t *testing.T) {
		// given:
		alice, bob := CreateActorsPair(t)

		// and: Alice (sender) has some certificate
		aliceCertManager := testcertificates.NewManager(t, alice.Wallet)

		aliceCert := aliceCertManager.CertificateForTest().WithType(contactCertTypeName).
			WithFieldValue(emailField, aliceName+"@example.com").
			Issue()

		// and: Bob is requesting certificates on initial handshake
		bob.CertificatesToRequest = &utils.RequestedCertificateSet{
			Certifiers: []*ec.PublicKey{aliceCert.WalletCert.Certifier},
			CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
				aliceCert.WalletCert.Type: []string{emailField},
			},
		}

		// when: callback registered
		var numberOfCalls int
		callbackID := bob.ListenForCertificatesReceived(func(_ context.Context, senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
			numberOfCalls++
			return nil
		})

		// and: alice sends a message
		err := alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000)
		require.NoError(t, err, "communication with listener failed")

		// then:
		require.Equal(t, 1, numberOfCalls, "Callback should have been called")

		// when: callback unregistered
		bob.StopListeningForCertificatesReceived(callbackID)

		// and: alice sends a message
		err = alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000)
		require.NoError(t, err, "communication after stop listening failed")

		// then:
		require.Equal(t, 1, numberOfCalls, "Only one callback should have been registered")
	})

	t.Run("ListenForCertificatesReceived - on certificate request", func(t *testing.T) {
		// given:
		alice, bob := CreateActorsPair(t)

		// and: Alice (sender) has some certificate
		aliceCertManager := testcertificates.NewManager(t, alice.Wallet)

		aliceCert := aliceCertManager.CertificateForTest().WithType(contactCertTypeName).
			WithFieldValue(emailField, aliceName+"@example.com").
			Issue()

		// when: callback registered
		var numberOfCalls int
		callbackID := bob.ListenForCertificatesReceived(func(_ context.Context, senderPublicKey *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
			numberOfCalls++
			return nil
		})

		// when: bob sends request for certificates
		certsToRequest := utils.RequestedCertificateSet{
			Certifiers: []*ec.PublicKey{aliceCert.WalletCert.Certifier},
			CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
				aliceCert.WalletCert.Type: []string{emailField},
			},
		}

		err := bob.RequestCertificates(t.Context(), alice.IdentityKey, certsToRequest, 500)
		require.NoError(t, err, "certificates request with listener failed")

		// then:
		require.Equal(t, 1, numberOfCalls, "Callback should have been called after request for certificates")

		// when: callback unregistered
		bob.StopListeningForCertificatesReceived(callbackID)

		// and: bob sends request for certificates again
		err = bob.RequestCertificates(t.Context(), alice.IdentityKey, *bob.CertificatesToRequest, 500)
		require.NoError(t, err, "certificates request with listener failed")

		// then:
		require.Equal(t, 1, numberOfCalls, "Only one callback should have been registered")
	})

	t.Run("ListenForCertificatesRequested - on message handling", func(t *testing.T) {
		// given:
		alice, bob := CreateActorsPair(t)

		// and: Alice (sender) has some certificate
		aliceCertManager := testcertificates.NewManager(t, alice.Wallet)

		aliceCert := aliceCertManager.CertificateForTest().WithType(contactCertTypeName).
			WithFieldValue(emailField, aliceName+"@example.com").
			Issue()

		// and: Bob is requesting certificates on initial handshake
		bob.CertificatesToRequest = &utils.RequestedCertificateSet{
			Certifiers: []*ec.PublicKey{aliceCert.WalletCert.Certifier},
			CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
				aliceCert.WalletCert.Type: []string{emailField},
			},
		}

		// when: callback registered
		var numberOfCalls int
		callbackID := alice.ListenForCertificatesRequested(func(_ context.Context, senderPublicKey *ec.PublicKey, requestedCertificates utils.RequestedCertificateSet) error {
			numberOfCalls++
			err := alice.SendCertificateResponse(t.Context(), senderPublicKey, []*certificates.VerifiableCertificate{aliceCert.ToVerifiableCertificate(senderPublicKey)})
			if err != nil {
				return fmt.Errorf("failed to send certificate to peer: %w", err)
			}
			return nil
		})

		// and: alice sends a message
		err := alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000)
		require.NoError(t, err, "communication with listener failed")

		// then:
		require.Equal(t, 1, numberOfCalls, "Callback should have been called")

		// when: callback unregistered
		alice.StopListeningForCertificatesRequested(callbackID)

		// and: alice sends a message again
		err = alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000)
		require.NoError(t, err, "communication after stop listening failed")

		// then:
		require.Equal(t, 1, numberOfCalls, "Only one callback should have been registered")
	})

	t.Run("ListenForCertificatesRequested - on certificate request", func(t *testing.T) {
		// given:
		alice, bob := CreateActorsPair(t)

		// and: Alice (sender) has some certificate
		aliceCertManager := testcertificates.NewManager(t, alice.Wallet)

		aliceCert := aliceCertManager.CertificateForTest().WithType(contactCertTypeName).
			WithFieldValue(emailField, aliceName+"@example.com").
			Issue()

		// when: callback registered
		var numberOfCalls int
		callbackID := alice.ListenForCertificatesRequested(func(_ context.Context, senderPublicKey *ec.PublicKey, requestedCertificates utils.RequestedCertificateSet) error {
			numberOfCalls++
			err := alice.SendCertificateResponse(t.Context(), senderPublicKey, []*certificates.VerifiableCertificate{aliceCert.ToVerifiableCertificate(senderPublicKey)})
			if err != nil {
				return fmt.Errorf("failed to send certificate to peer: %w", err)
			}
			return nil
		})

		// and: bob sends request for certificates
		certsToRequest := utils.RequestedCertificateSet{
			Certifiers: []*ec.PublicKey{aliceCert.WalletCert.Certifier},
			CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{
				aliceCert.WalletCert.Type: []string{emailField},
			},
		}

		err := bob.RequestCertificates(t.Context(), alice.IdentityKey, certsToRequest, 500)
		require.NoError(t, err, "certificates request with listener failed")

		// then:
		require.Equal(t, 1, numberOfCalls, "Callback should have been called after request for certificates")

		// when: callback unregistered
		alice.StopListeningForCertificatesRequested(callbackID)

		// and: bob sends request for certificates again
		err = bob.RequestCertificates(t.Context(), alice.IdentityKey, *bob.CertificatesToRequest, 500)
		require.NoError(t, err, "certificates request with listener failed")

		// then:
		require.Equal(t, 1, numberOfCalls, "Only one callback should have been registered")
	})
}
