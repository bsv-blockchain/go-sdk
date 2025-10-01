package main

import (
	"context"
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
	callback func(context.Context, *auth.AuthMessage) error
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

func (t *MemoryTransport) Send(ctx context.Context, message *auth.AuthMessage) error {
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
			_ = receiver.callback(ctx, message)
		}
	}()

	return nil
}

func (t *MemoryTransport) OnData(callback func(context.Context, *auth.AuthMessage) error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.callback = callback
	return nil
}

func (t *MemoryTransport) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.callback == nil {
		return nil, fmt.Errorf("no callback registered")
	}

	return t.callback, nil
}

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
	aliceIdentityResult, _ := aliceWallet.GetPublicKey(context.Background(), wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, "example")
	aliceIdentity := hex.EncodeToString(aliceIdentityResult.PublicKey.Compressed())

	bobIdentityResult, _ := bobWallet.GetPublicKey(context.Background(), wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, "example")
	bobIdentity := hex.EncodeToString(bobIdentityResult.PublicKey.Compressed())

	fmt.Printf("Alice's identity key: %s\n", aliceIdentity)
	fmt.Printf("Bob's identity key: %s\n", bobIdentity)

	// Set up message listeners
	alicePeer.ListenForGeneralMessages(func(_ context.Context, senderPublicKey *ec.PublicKey, payload []byte) error {
		fmt.Printf("Alice received message from %s: %s\n", senderPublicKey.Compressed(), string(payload))
		return nil
	})

	bobPeer.ListenForGeneralMessages(func(_ context.Context, senderPublicKey *ec.PublicKey, payload []byte) error {
		fmt.Printf("Bob received message from %s: %s\n", senderPublicKey.Compressed(), string(payload))

		// Reply to Alice
		err := bobPeer.ToPeer(context.Background(), []byte("Hello back, Alice!"), senderPublicKey, 5000)
		if err != nil {
			log.Printf("Bob failed to reply: %v", err)
		}
		return nil
	})

	// Alice sends a message to Bob
	err = alicePeer.ToPeer(context.Background(), []byte("Hello, Bob!"), bobIdentityResult.PublicKey, 5000)
	if err != nil {
		log.Fatalf("Failed to send message: %v", err)
	}

	// Wait for messages to be processed
	time.Sleep(1 * time.Second)

	fmt.Println("Example completed successfully!")
}
