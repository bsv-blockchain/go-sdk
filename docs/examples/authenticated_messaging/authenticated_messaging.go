package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// MemoryTransport implements auth.Transport for in-memory message passing
type MemoryTransport struct {
	callback func(*auth.AuthMessage) error
	receiver *MemoryTransport
	mu       sync.Mutex
}

func NewMemoryTransport() *MemoryTransport {
	return &MemoryTransport{
		mu: sync.Mutex{},
	}
}

func (t *MemoryTransport) Connect(other *MemoryTransport) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.receiver = other
}

func (t *MemoryTransport) Send(message *auth.AuthMessage) error {
	t.mu.Lock()
	receiver := t.receiver
	t.mu.Unlock()

	if receiver == nil {
		return fmt.Errorf("transport not connected to a receiver")
	}

	// Simulate network delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		if receiver.callback != nil {
			_ = receiver.callback(message)
		}
	}()

	return nil
}

func (t *MemoryTransport) OnData(callback func(*auth.AuthMessage) error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.callback = callback
	return nil
}

// MinimalWalletImpl is a minimal implementation of wallet.Interface
type MinimalWalletImpl struct {
	*wallet.Wallet
}

// Required methods to satisfy wallet.Interface
func (w *MinimalWalletImpl) CreateAction(args wallet.CreateActionArgs, context string) (*wallet.CreateActionResult, error) {
	return &wallet.CreateActionResult{Txid: "mock_tx", Tx: []byte{}}, nil
}

func (w *MinimalWalletImpl) ListCertificates(args wallet.ListCertificatesArgs) (*wallet.ListCertificatesResult, error) {
	return &wallet.ListCertificatesResult{Certificates: []wallet.Certificate{}}, nil
}

func (w *MinimalWalletImpl) ProveCertificate(args wallet.ProveCertificateArgs) (*wallet.ProveCertificateResult, error) {
	return &wallet.ProveCertificateResult{KeyringForVerifier: map[string]string{}}, nil
}

func (w *MinimalWalletImpl) IsAuthenticated(args interface{}) (bool, error) {
	return true, nil
}

func (w *MinimalWalletImpl) GetHeight(args interface{}) (uint32, error) {
	return 0, nil
}

func (w *MinimalWalletImpl) GetNetwork(args interface{}) (string, error) {
	return "test", nil
}

func (w *MinimalWalletImpl) GetVersion(args interface{}) (string, error) {
	return "1.0", nil
}

func main() {
	// Create two transport pairs
	aliceTransport := NewMemoryTransport()
	bobTransport := NewMemoryTransport()

	// Connect the transports
	aliceTransport.Connect(bobTransport)
	bobTransport.Connect(aliceTransport)

	// Create two wallets with random keys
	aliceKeyBytes := make([]byte, 32)
	_, _ = rand.Read(aliceKeyBytes)
	alicePrivKey, _ := ec.PrivateKeyFromBytes(aliceKeyBytes)

	bobKeyBytes := make([]byte, 32)
	_, _ = rand.Read(bobKeyBytes)
	bobPrivKey, _ := ec.PrivateKeyFromBytes(bobKeyBytes)

	aliceWallet := &MinimalWalletImpl{Wallet: wallet.NewWallet(alicePrivKey)}
	bobWallet := &MinimalWalletImpl{Wallet: wallet.NewWallet(bobPrivKey)}

	// Create peers
	alicePeer := auth.NewPeer(&auth.PeerOptions{
		Wallet:    aliceWallet,
		Transport: aliceTransport,
	})

	bobPeer := auth.NewPeer(&auth.PeerOptions{
		Wallet:    bobWallet,
		Transport: bobTransport,
	})

	// Get identity keys
	aliceIdentityResult, _ := aliceWallet.GetPublicKey(&wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, "example")
	aliceIdentity := hex.EncodeToString(aliceIdentityResult.PublicKey.Compressed())

	bobIdentityResult, _ := bobWallet.GetPublicKey(&wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, "example")
	bobIdentity := hex.EncodeToString(bobIdentityResult.PublicKey.Compressed())

	fmt.Printf("Alice's identity key: %s\n", aliceIdentity)
	fmt.Printf("Bob's identity key: %s\n", bobIdentity)

	// Set up message listeners
	alicePeer.ListenForGeneralMessages(func(senderPublicKey string, payload []byte) error {
		fmt.Printf("Alice received message from %s: %s\n", senderPublicKey, string(payload))
		return nil
	})

	bobPeer.ListenForGeneralMessages(func(senderPublicKey string, payload []byte) error {
		fmt.Printf("Bob received message from %s: %s\n", senderPublicKey, string(payload))

		// Reply to Alice
		err := bobPeer.ToPeer([]byte("Hello back, Alice!"), senderPublicKey, 5000)
		if err != nil {
			log.Printf("Bob failed to reply: %v", err)
		}
		return nil
	})

	// Alice sends a message to Bob
	err := alicePeer.ToPeer([]byte("Hello, Bob!"), bobIdentity, 5000)
	if err != nil {
		log.Fatalf("Failed to send message: %v", err)
	}

	// Wait for messages to be processed
	time.Sleep(1 * time.Second)

	fmt.Println("Example completed successfully!")
}
