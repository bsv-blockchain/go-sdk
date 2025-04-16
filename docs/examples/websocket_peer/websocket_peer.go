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
func (w *MinimalWalletImpl) CreateAction(ctx context.Context, args wallet.CreateActionArgs, context string) (*wallet.CreateActionResult, error) {
	return &wallet.CreateActionResult{Txid: "mock_tx", Tx: []byte{}}, nil
}

func (w *MinimalWalletImpl) ListCertificates(ctx context.Context, args wallet.ListCertificatesArgs) (*wallet.ListCertificatesResult, error) {
	return &wallet.ListCertificatesResult{Certificates: []wallet.CertificateResult{}}, nil
}

func (w *MinimalWalletImpl) ProveCertificate(ctx context.Context, args wallet.ProveCertificateArgs) (*wallet.ProveCertificateResult, error) {
	return &wallet.ProveCertificateResult{KeyringForVerifier: map[string]string{}}, nil
}

func (w *MinimalWalletImpl) IsAuthenticated(ctx context.Context, args interface{}, originator string) (*wallet.AuthenticatedResult, error) {
	return &wallet.AuthenticatedResult{Authenticated: true}, nil
}

func (w *MinimalWalletImpl) GetHeight(ctx context.Context, args interface{}, originator string) (*wallet.GetHeightResult, error) {
	return &wallet.GetHeightResult{}, nil
}

func (w *MinimalWalletImpl) GetNetwork(ctx context.Context, args interface{}, originator string) (*wallet.GetNetworkResult, error) {
	return &wallet.GetNetworkResult{Network: "test"}, nil
}

func (w *MinimalWalletImpl) GetVersion(ctx context.Context, args interface{}, originator string) (*wallet.GetVersionResult, error) {
	return &wallet.GetVersionResult{Version: "1.0"}, nil
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
	onDataFuncs []func(*auth.AuthMessage) error
	mu          sync.Mutex
}

func newMockTransport(clientID string, server *mockWebSocketServer) *mockTransport {
	return &mockTransport{
		clientID: clientID,
		server:   server,
	}
}

func (t *mockTransport) Connect() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.connected {
		return fmt.Errorf("already connected")
	}

	t.connected = true

	// Register with the server to receive messages
	t.server.registerClient(t.clientID, func(msg *auth.AuthMessage) {
		t.handleMessage(msg)
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

func (t *mockTransport) Send(message *auth.AuthMessage) error {
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

func (t *mockTransport) OnData(callback func(*auth.AuthMessage) error) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.onDataFuncs = append(t.onDataFuncs, callback)
	return nil
}

func (t *mockTransport) handleMessage(message *auth.AuthMessage) {
	t.mu.Lock()
	handlers := make([]func(*auth.AuthMessage) error, len(t.onDataFuncs))
	copy(handlers, t.onDataFuncs)
	t.mu.Unlock()

	for _, handler := range handlers {
		// Errors from handlers are not propagated
		_ = handler(message)
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

	aliceWallet := &MinimalWalletImpl{Wallet: wallet.NewWallet(alicePrivKey)}
	bobWallet := &MinimalWalletImpl{Wallet: wallet.NewWallet(bobPrivKey)}

	// Connect transports
	err := aliceTransport.Connect()
	if err != nil {
		log.Fatalf("Failed to connect Alice's transport: %v", err)
	}
	defer aliceTransport.Disconnect()

	err = bobTransport.Connect()
	if err != nil {
		log.Fatalf("Failed to connect Bob's transport: %v", err)
	}
	defer bobTransport.Disconnect()

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
	alicePeer.ListenForGeneralMessages(func(senderPublicKey string, payload []byte) error {
		fmt.Printf("Alice received message from %s: %s\n", senderPublicKey, string(payload))
		return nil
	})

	bobPeer.ListenForGeneralMessages(func(senderPublicKey string, payload []byte) error {
		fmt.Printf("Bob received message from %s: %s\n", senderPublicKey, string(payload))
		return nil
	})

	// Get identity keys
	aliceIdentityKey, _ := aliceWallet.GetPublicKey(context.TODO(), wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, "example")

	bobIdentityKey, _ := bobWallet.GetPublicKey(context.TODO(), wallet.GetPublicKeyArgs{
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
	err = alicePeer.ToPeer([]byte("Hello Bob, this is Alice!"), bobIdKeyString, 5000)
	if err != nil {
		log.Fatalf("Failed to send message from Alice to Bob: %v", err)
	}

	// Wait briefly
	time.Sleep(500 * time.Millisecond)

	// Bob replies to Alice
	fmt.Println("Bob is replying to Alice...")
	err = bobPeer.ToPeer([]byte("Hello Alice, nice to hear from you!"), aliceIdKeyString, 5000)
	if err != nil {
		log.Fatalf("Failed to send message from Bob to Alice: %v", err)
	}

	// Wait for Ctrl+C to exit
	fmt.Println("\nPress Ctrl+C to exit")
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}
