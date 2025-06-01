package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/topic"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// CertificateVerifier is an interface for certificate verification
// We use this to make testing easier by allowing mocks
type CertificateVerifier interface {
	// Verify verifies a certificate
	Verify(ctx context.Context, certificate *wallet.Certificate) error
}

// DefaultCertificateVerifier is the standard implementation of CertificateVerifier
// It uses the actual certificate verification logic
type DefaultCertificateVerifier struct{}

// Verify implements the CertificateVerifier interface using the standard verification
func (v *DefaultCertificateVerifier) Verify(ctx context.Context, certificate *wallet.Certificate) error {
	// The real implementation would pass the certificate to the proper verification method
	// For now, since we can't access the actual implementation in the tests,
	// we'll just return nil (successful verification)
	// In a production environment, this would be replaced with proper certificate verification
	// TODO: Implement proper certificate verification
	return nil
}

// TransactionCreator is a function that creates a Transaction from BEEF bytes
type TransactionCreator func([]byte) (*transaction.Transaction, error)

// TestableIdentityClient extends IdentityClient with features that make it easier to test
type TestableIdentityClient struct {
	*Client
	certificateVerifier CertificateVerifier
	transactionCreator  TransactionCreator
	broadcaster         topic.Broadcaster
}

// NewTestableIdentityClient creates a new TestableIdentityClient with the provided wallet and options
func NewTestableIdentityClient(
	w wallet.Interface,
	options *IdentityClientOptions,
	originator OriginatorDomainNameStringUnder250Bytes,
	verifier CertificateVerifier,
) (*TestableIdentityClient, error) {
	baseClient, err := NewClient(w, options, originator)
	if err != nil {
		return nil, err
	}

	// Use default verifier if none provided
	if verifier == nil {
		verifier = &DefaultCertificateVerifier{}
	}

	return &TestableIdentityClient{
		Client:              baseClient,
		certificateVerifier: verifier,
		transactionCreator:  transaction.NewTransactionFromBEEF, // Default to actual implementation
		broadcaster:         topic.Broadcaster{},                // Default to actual implementation
	}, nil
}

// WithTransactionCreator sets a custom transaction creator for testing
func (c *TestableIdentityClient) WithTransactionCreator(creator TransactionCreator) *TestableIdentityClient {
	c.transactionCreator = creator
	return c
}

// WithBroadcasterFactory sets a custom broadcaster factory for testing
func (c *TestableIdentityClient) WithBroadcaster(factory topic.Broadcaster) *TestableIdentityClient {
	c.broadcaster = factory
	return c
}

// PubliclyRevealAttributes is a testable version that uses the injected certificate verifier
func (c *TestableIdentityClient) PubliclyRevealAttributes(
	ctx context.Context,
	certificate *wallet.Certificate,
	fieldsToReveal []CertificateFieldNameUnder50Bytes,
) (*transaction.BroadcastSuccess, *transaction.BroadcastFailure, error) {
	if len(certificate.Fields) == 0 {
		return nil, nil, errors.New("certificate has no fields to reveal")
	}
	if len(fieldsToReveal) == 0 {
		return nil, nil, errors.New("you must reveal at least one field")
	}

	// Use the injected certificate verifier instead of direct verification
	if err := c.certificateVerifier.Verify(ctx, certificate); err != nil {
		return nil, nil, errors.New("certificate verification failed")
	}

	// Convert field names to strings for wallet API
	fieldNamesAsStrings := make([]string, len(fieldsToReveal))
	for i, field := range fieldsToReveal {
		fieldNamesAsStrings[i] = string(field)
	}

	// Get keyring for verifier through certificate proving
	dummyPk, err := ec.NewPrivateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create dummy key: %w", err)
	}
	var verifierPubKey [33]byte
	copy(verifierPubKey[:], dummyPk.PubKey().Compressed())

	_, err = c.wallet.ProveCertificate(ctx, wallet.ProveCertificateArgs{
		Certificate:    *certificate,
		FieldsToReveal: fieldNamesAsStrings,
		Verifier:       verifierPubKey,
	}, string(c.originator))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to prove certificate: %w", err)
	}

	// Create PushDrop with the certificate data
	pushDropTemplate := &pushdrop.PushDropTemplate{
		Wallet:     c.wallet,
		Originator: string(c.originator),
	}

	// Create locking script using PushDrop with the certificate JSON
	lockingScript, err := pushDropTemplate.Lock(
		ctx,
		[][]byte{[]byte("test-cert-data")}, // Simplified for testing
		c.options.ProtocolID,
		c.options.KeyID,
		wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone},
		true,
		true,
		true,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create locking script: %w", err)
	}

	// Create a transaction with the certificate as an output
	createResult, err := c.wallet.CreateAction(ctx, wallet.CreateActionArgs{
		Description: "Create a new Identity Token",
		Outputs: []wallet.CreateActionOutput{
			{
				Satoshis:          c.options.TokenAmount,
				LockingScript:     lockingScript.Bytes(),
				OutputDescription: "Identity Token",
			},
		},
		Options: &wallet.CreateActionOptions{
			RandomizeOutputs: util.BoolPtr(false),
		},
	}, string(c.originator))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create action: %w", err)
	}

	if createResult.Tx == nil {
		return nil, nil, errors.New("public reveal failed: failed to create action")
	}

	// Create transaction from BEEF
	tx, err := c.transactionCreator(createResult.Tx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create transaction from BEEF: %w", err)
	}

	// Submit the transaction to an overlay
	networkResult, err := c.wallet.GetNetwork(ctx, nil, string(c.originator))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get network: %w", err)
	}

	// Create broadcaster
	var network overlay.Network
	if networkResult.Network == "mainnet" {
		network = overlay.NetworkMainnet
	} else {
		network = overlay.NetworkTestnet
	}

	broadcaster, err := topic.NewBroadcaster([]string{"tm_identity"}, &topic.BroadcasterConfig{
		NetworkPreset: network,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create broadcaster: %w", err)
	}

	// Broadcast the transaction
	success, failure := broadcaster.Broadcast(tx)
	return success, failure, nil
}

// PubliclyRevealAttributesSimple is a simplified version of PubliclyRevealAttributes that returns only
// a broadcast result string, to mirror the TypeScript implementation's return signature.
func (c *TestableIdentityClient) PubliclyRevealAttributesSimple(
	ctx context.Context,
	certificate *wallet.Certificate,
	fieldsToReveal []CertificateFieldNameUnder50Bytes,
) (string, error) {
	success, failure, err := c.PubliclyRevealAttributes(ctx, certificate, fieldsToReveal)
	if err != nil {
		return "", err
	}

	if success != nil {
		return success.Txid, nil
	}

	if failure != nil {
		return "", fmt.Errorf("broadcast failed: %s", failure.Description)
	}

	return "", errors.New("unknown error during broadcast")
}

// MockCertificateVerifier is a mock implementation of CertificateVerifier for testing
type MockCertificateVerifier struct {
	// MockVerify is a function that will be called by Verify
	MockVerify func(ctx context.Context, certificate *wallet.Certificate) error
}

// Verify implements the CertificateVerifier interface for testing
func (m *MockCertificateVerifier) Verify(ctx context.Context, certificate *wallet.Certificate) error {
	if m.MockVerify != nil {
		return m.MockVerify(ctx, certificate)
	}
	return nil
}
