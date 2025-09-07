package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// MinimalWalletImpl is a minimal implementation of wallet.Interface
type MinimalWalletImpl struct {
	*wallet.Wallet
}

// Required methods to satisfy wallet.Interface
func (w *MinimalWalletImpl) CreateAction(ctx context.Context, args wallet.CreateActionArgs, originator string) (*wallet.CreateActionResult, error) {
	return &wallet.CreateActionResult{Txid: [32]byte{0x01, 0x02}, Tx: []byte{}}, nil
}

func (w *MinimalWalletImpl) ListCertificates(ctx context.Context, args wallet.ListCertificatesArgs, originator string) (*wallet.ListCertificatesResult, error) {
	return &wallet.ListCertificatesResult{Certificates: []wallet.CertificateResult{}}, nil
}

func (w *MinimalWalletImpl) ProveCertificate(ctx context.Context, args wallet.ProveCertificateArgs, originator string) (*wallet.ProveCertificateResult, error) {
	return &wallet.ProveCertificateResult{KeyringForVerifier: map[string]string{}}, nil
}

func (w *MinimalWalletImpl) IsAuthenticated(ctx context.Context, args any, originator string) (*wallet.AuthenticatedResult, error) {
	return &wallet.AuthenticatedResult{Authenticated: true}, nil
}

func (w *MinimalWalletImpl) GetHeight(ctx context.Context, args any, originator string) (*wallet.GetHeightResult, error) {
	return &wallet.GetHeightResult{Height: 0}, nil
}

func (w *MinimalWalletImpl) GetNetwork(ctx context.Context, args any, originator string) (*wallet.GetNetworkResult, error) {
	return &wallet.GetNetworkResult{Network: wallet.NetworkTestnet}, nil
}

func (w *MinimalWalletImpl) GetVersion(ctx context.Context, args any, originator string) (*wallet.GetVersionResult, error) {
	return &wallet.GetVersionResult{Version: "1.0"}, nil
}

func (w *MinimalWalletImpl) AbortAction(ctx context.Context, args wallet.AbortActionArgs, originator string) (*wallet.AbortActionResult, error) {
	return &wallet.AbortActionResult{}, nil
}

func (w *MinimalWalletImpl) AcquireCertificate(ctx context.Context, args wallet.AcquireCertificateArgs, originator string) (*wallet.Certificate, error) {
	return &wallet.Certificate{}, nil
}

func (w *MinimalWalletImpl) DiscoverByAttributes(ctx context.Context, args wallet.DiscoverByAttributesArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	return &wallet.DiscoverCertificatesResult{}, nil
}

func (w *MinimalWalletImpl) DiscoverByIdentityKey(ctx context.Context, args wallet.DiscoverByIdentityKeyArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	return &wallet.DiscoverCertificatesResult{}, nil
}

func (w *MinimalWalletImpl) GetHeaderForHeight(ctx context.Context, args wallet.GetHeaderArgs, originator string) (*wallet.GetHeaderResult, error) {
	return &wallet.GetHeaderResult{}, nil
}

func (w *MinimalWalletImpl) InternalizeAction(ctx context.Context, args wallet.InternalizeActionArgs, originator string) (*wallet.InternalizeActionResult, error) {
	return &wallet.InternalizeActionResult{}, nil
}

func (w *MinimalWalletImpl) ListOutputs(ctx context.Context, args wallet.ListOutputsArgs, originator string) (*wallet.ListOutputsResult, error) {
	return &wallet.ListOutputsResult{}, nil
}

func (w *MinimalWalletImpl) ListActions(ctx context.Context, args wallet.ListActionsArgs, originator string) (*wallet.ListActionsResult, error) {
	return &wallet.ListActionsResult{}, nil
}

func (w *MinimalWalletImpl) RelinquishCertificate(ctx context.Context, args wallet.RelinquishCertificateArgs, originator string) (*wallet.RelinquishCertificateResult, error) {
	return &wallet.RelinquishCertificateResult{}, nil
}

func (w *MinimalWalletImpl) SignAction(ctx context.Context, args wallet.SignActionArgs, originator string) (*wallet.SignActionResult, error) {
	return &wallet.SignActionResult{}, nil
}

func (w *MinimalWalletImpl) RelinquishOutput(ctx context.Context, args wallet.RelinquishOutputArgs, originator string) (*wallet.RelinquishOutputResult, error) {
	return &wallet.RelinquishOutputResult{}, nil
}

func (w *MinimalWalletImpl) RevealCounterpartyKeyLinkage(ctx context.Context, args wallet.RevealCounterpartyKeyLinkageArgs, originator string) (*wallet.RevealCounterpartyKeyLinkageResult, error) {
	return &wallet.RevealCounterpartyKeyLinkageResult{}, nil
}

func (w *MinimalWalletImpl) RevealSpecificKeyLinkage(ctx context.Context, args wallet.RevealSpecificKeyLinkageArgs, originator string) (*wallet.RevealSpecificKeyLinkageResult, error) {
	return &wallet.RevealSpecificKeyLinkageResult{}, nil
}

func (w *MinimalWalletImpl) WaitForAuthentication(ctx context.Context, args any, originator string) (*wallet.AuthenticatedResult, error) {
	return &wallet.AuthenticatedResult{Authenticated: true}, nil
}

// mockWebSocketServer is a simple in-memory message broker for testing
type mockWebSocketServer struct {
	clients map[string][]func(*auth.AuthMessage)
	mu      sync.Mutex
}

func newMockWebSocketServer() *mockWebSocketServer {
	return &mockWebSocketServer{
		clients: make(map[string][]func(*auth.AuthMessage)),
	}
}

func (s *mockWebSocketServer) registerClient(clientID string, callback func(*auth.AuthMessage)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	callbacks, ok := s.clients[clientID]
	if !ok {
		callbacks = []func(*auth.AuthMessage){}
	}

	s.clients[clientID] = append(callbacks, callback)
}

func (s *mockWebSocketServer) unregisterClient(clientID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.clients, clientID)
}

func (s *mockWebSocketServer) broadcast(message *auth.AuthMessage, sourceID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Send to all clients except the source
	for clientID, callbacks := range s.clients {
		if clientID != sourceID {
			for _, callback := range callbacks {
				// Clone the message to avoid race conditions
				messageCopy := *message
				go callback(&messageCopy)
			}
		}
	}
}

// mockTransport implements the auth.Transport interface for testing
type mockTransport struct {
	clientID    string
	server      *mockWebSocketServer
	connected   bool
	onDataFuncs []func(context.Context, *auth.AuthMessage) error
	mu          sync.Mutex
}

func newMockTransport(clientID string, server *mockWebSocketServer) *mockTransport {
	return &mockTransport{
		clientID: clientID,
		server:   server,
	}
}

func (t *mockTransport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.connected {
		return fmt.Errorf("already connected")
	}

	t.connected = true

	// Register with the server to receive messages
	t.server.registerClient(t.clientID, func(msg *auth.AuthMessage) {
		t.handleMessage(ctx, msg)
	})

	return nil
}

func (t *mockTransport) Disconnect() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.connected {
		return nil
	}

	t.connected = false
	t.server.unregisterClient(t.clientID)
	return nil
}

func (t *mockTransport) Send(ctx context.Context, message *auth.AuthMessage) error {
	t.mu.Lock()
	connected := t.connected
	t.mu.Unlock()

	if !connected {
		return fmt.Errorf("not connected")
	}

	// Broadcast the message to all other clients
	t.server.broadcast(message, t.clientID)
	return nil
}

func (t *mockTransport) OnData(callback func(context.Context, *auth.AuthMessage) error) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.onDataFuncs = append(t.onDataFuncs, callback)
	return nil
}

func (t *mockTransport) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.onDataFuncs) == 0 {
		return nil, fmt.Errorf("no registered onData functions")
	}

	return t.onDataFuncs[0], nil
}

func (t *mockTransport) handleMessage(ctx context.Context, message *auth.AuthMessage) {
	t.mu.Lock()
	handlers := make([]func(context.Context, *auth.AuthMessage) error, len(t.onDataFuncs))
	copy(handlers, t.onDataFuncs)
	t.mu.Unlock()

	for _, handler := range handlers {
		// Errors from handlers are not propagated
		_ = handler(ctx, message)
	}
}

func main() {
	// Create mock WebSocket server
	server := newMockWebSocketServer()

	// Create transports
	aliceTransport := newMockTransport("alice", server)
	bobTransport := newMockTransport("bob", server)

	// Create wallets with random keys
	aliceKeyBytes := make([]byte, 32)
	_, _ = rand.Read(aliceKeyBytes)
	alicePrivKey, _ := ec.PrivateKeyFromBytes(aliceKeyBytes)

	bobKeyBytes := make([]byte, 32)
	_, _ = rand.Read(bobKeyBytes)
	bobPrivKey, _ := ec.PrivateKeyFromBytes(bobKeyBytes)

	aliceW, err := wallet.NewWallet(alicePrivKey)
	if err != nil {
		log.Fatalf("Failed to create alice wallet: %v", err)
	}
	aliceWallet := &MinimalWalletImpl{Wallet: aliceW}

	bobW, err := wallet.NewWallet(bobPrivKey)
	if err != nil {
		log.Fatalf("Failed to create bob wallet: %v", err)
	}
	bobWallet := &MinimalWalletImpl{Wallet: bobW}

	// Connect transports
	err = aliceTransport.Connect(context.Background())
	if err != nil {
		log.Fatalf("Failed to connect Alice's transport: %v", err)
	}
	defer func() { _ = aliceTransport.Disconnect() }()

	err = bobTransport.Connect(context.Background())
	if err != nil {
		log.Fatalf("Failed to connect Bob's transport: %v", err)
	}
	defer func() { _ = bobTransport.Disconnect() }()

	// Create peers
	alicePeer := auth.NewPeer(&auth.PeerOptions{
		Wallet:    aliceWallet,
		Transport: aliceTransport,
	})

	bobPeer := auth.NewPeer(&auth.PeerOptions{
		Wallet:    bobWallet,
		Transport: bobTransport,
	})

	// Set up message handlers
	alicePeer.ListenForGeneralMessages(func(_ context.Context, senderPubKey *ec.PublicKey, payload []byte) error {

		fmt.Printf("Alice received message from %s: %s\n", senderPubKey.Compressed(), string(payload))
		return nil
	})

	bobPeer.ListenForGeneralMessages(func(_ context.Context, senderPubKey *ec.PublicKey, payload []byte) error {
		fmt.Printf("Bob received message from %s: %s\n", senderPubKey.Compressed(), string(payload))
		return nil
	})

	// Get identity keys
	aliceIdentityKey, _ := aliceWallet.GetPublicKey(context.Background(), wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, "example")

	bobIdentityKey, _ := bobWallet.GetPublicKey(context.Background(), wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, "example")

	aliceIdKeyString := hex.EncodeToString(aliceIdentityKey.PublicKey.Compressed())
	bobIdKeyString := hex.EncodeToString(bobIdentityKey.PublicKey.Compressed())

	fmt.Printf("Alice's identity key: %s\n", aliceIdKeyString)
	fmt.Printf("Bob's identity key: %s\n", bobIdKeyString)

	// Wait a moment for connections to establish
	time.Sleep(500 * time.Millisecond)

	// Alice sends a message to Bob
	fmt.Println("Alice is sending a message to Bob...")
	err = alicePeer.ToPeer(context.Background(), []byte("Hello Bob, this is Alice!"), bobIdentityKey.PublicKey, 5000)
	if err != nil {
		log.Fatalf("Failed to send message from Alice to Bob: %v", err)
	}

	// Wait briefly
	time.Sleep(500 * time.Millisecond)

	// Bob replies to Alice
	fmt.Println("Bob is replying to Alice...")
	err = bobPeer.ToPeer(context.Background(), []byte("Hello Alice, nice to hear from you!"), aliceIdentityKey.PublicKey, 5000)
	if err != nil {
		log.Fatalf("Failed to send message from Bob to Alice: %v", err)
	}

	// Wait for Ctrl+C to exit
	fmt.Println("\nPress Ctrl+C to exit")
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}
