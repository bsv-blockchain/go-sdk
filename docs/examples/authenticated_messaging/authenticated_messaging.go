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
func (w *MinimalWalletImpl) CreateAction(args wallet.CreateActionArgs, originator string) (*wallet.CreateActionResult, error) {
	return &wallet.CreateActionResult{Txid: "mock_tx", Tx: []byte{}}, nil
}

func (w *MinimalWalletImpl) ListCertificates(args wallet.ListCertificatesArgs, originator string) (*wallet.ListCertificatesResult, error) {
	return &wallet.ListCertificatesResult{Certificates: []wallet.CertificateResult{}}, nil
}

func (w *MinimalWalletImpl) ProveCertificate(args wallet.ProveCertificateArgs, originator string) (*wallet.ProveCertificateResult, error) {
	return &wallet.ProveCertificateResult{KeyringForVerifier: map[string]string{}}, nil
}

func (w *MinimalWalletImpl) IsAuthenticated(args interface{}, originator string) (*wallet.AuthenticatedResult, error) {
	return &wallet.AuthenticatedResult{Authenticated: true}, nil
}

func (w *MinimalWalletImpl) GetHeight(args interface{}, originator string) (*wallet.GetHeightResult, error) {
	return &wallet.GetHeightResult{Height: 0}, nil
}

func (w *MinimalWalletImpl) GetNetwork(args interface{}, originator string) (*wallet.GetNetworkResult, error) {
	return &wallet.GetNetworkResult{Network: "test"}, nil
}

func (w *MinimalWalletImpl) GetVersion(args interface{}, originator string) (*wallet.GetVersionResult, error) {
	return &wallet.GetVersionResult{Version: "1.0"}, nil
}

func (w *MinimalWalletImpl) AbortAction(args wallet.AbortActionArgs, originator string) (*wallet.AbortActionResult, error) {
	return &wallet.AbortActionResult{}, nil
}

func (w *MinimalWalletImpl) AcquireCertificate(args wallet.AcquireCertificateArgs, originator string) (*wallet.Certificate, error) {
	return &wallet.Certificate{}, nil
}

func (w *MinimalWalletImpl) DiscoverByAttributes(args wallet.DiscoverByAttributesArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	return &wallet.DiscoverCertificatesResult{}, nil
}

func (w *MinimalWalletImpl) DiscoverByIdentityKey(args wallet.DiscoverByIdentityKeyArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
	return &wallet.DiscoverCertificatesResult{}, nil
}

func (w *MinimalWalletImpl) GetHeaderForHeight(args wallet.GetHeaderArgs, originator string) (*wallet.GetHeaderResult, error) {
	return &wallet.GetHeaderResult{}, nil
}

func (w *MinimalWalletImpl) InternalizeAction(args wallet.InternalizeActionArgs, originator string) (*wallet.InternalizeActionResult, error) {
	return &wallet.InternalizeActionResult{}, nil
}

func (w *MinimalWalletImpl) ListOutputs(args wallet.ListOutputsArgs, originator string) (*wallet.ListOutputsResult, error) {
	return &wallet.ListOutputsResult{}, nil
}

func (w *MinimalWalletImpl) ListActions(args wallet.ListActionsArgs, originator string) (*wallet.ListActionsResult, error) {
	return &wallet.ListActionsResult{}, nil
}

func (w *MinimalWalletImpl) RelinquishCertificate(args wallet.RelinquishCertificateArgs, originator string) (*wallet.RelinquishCertificateResult, error) {
	return &wallet.RelinquishCertificateResult{}, nil
}

func (w *MinimalWalletImpl) SignAction(args wallet.SignActionArgs, originator string) (*wallet.SignActionResult, error) {
	return &wallet.SignActionResult{}, nil
}

func (w *MinimalWalletImpl) RelinquishOutput(args wallet.RelinquishOutputArgs, originator string) (*wallet.RelinquishOutputResult, error) {
	return &wallet.RelinquishOutputResult{}, nil
}

func (w *MinimalWalletImpl) RevealCounterpartyKeyLinkage(args wallet.RevealCounterpartyKeyLinkageArgs, originator string) (*wallet.RevealCounterpartyKeyLinkageResult, error) {
	return &wallet.RevealCounterpartyKeyLinkageResult{}, nil
}

func (w *MinimalWalletImpl) RevealSpecificKeyLinkage(args wallet.RevealSpecificKeyLinkageArgs, originator string) (*wallet.RevealSpecificKeyLinkageResult, error) {
	return &wallet.RevealSpecificKeyLinkageResult{}, nil
}

func (w *MinimalWalletImpl) WaitForAuthentication(args interface{}, originator string) (*wallet.AuthenticatedResult, error) {
	return &wallet.AuthenticatedResult{Authenticated: true}, nil
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
	aliceIdentityResult, _ := aliceWallet.GetPublicKey(wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, "example")
	aliceIdentity := hex.EncodeToString(aliceIdentityResult.PublicKey.Compressed())

	bobIdentityResult, _ := bobWallet.GetPublicKey(wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, "example")
	bobIdentity := hex.EncodeToString(bobIdentityResult.PublicKey.Compressed())

	fmt.Printf("Alice's identity key: %s\n", aliceIdentity)
	fmt.Printf("Bob's identity key: %s\n", bobIdentity)

	// Set up message listeners
	alicePeer.ListenForGeneralMessages(func(senderPublicKey *ec.PublicKey, payload []byte) error {
		fmt.Printf("Alice received message from %s: %s\n", senderPublicKey.Compressed(), string(payload))
		return nil
	})

	bobPeer.ListenForGeneralMessages(func(senderPublicKey *ec.PublicKey, payload []byte) error {
		fmt.Printf("Bob received message from %s: %s\n", senderPublicKey.Compressed(), string(payload))

		// Reply to Alice
		err := bobPeer.ToPeer([]byte("Hello back, Alice!"), senderPublicKey, 5000)
		if err != nil {
			log.Printf("Bob failed to reply: %v", err)
		}
		return nil
	})

	// Alice sends a message to Bob
	err := alicePeer.ToPeer([]byte("Hello, Bob!"), bobIdentityResult.PublicKey, 5000)
	if err != nil {
		log.Fatalf("Failed to send message: %v", err)
	}

	// Wait for messages to be processed
	time.Sleep(1 * time.Second)

	fmt.Println("Example completed successfully!")
}
