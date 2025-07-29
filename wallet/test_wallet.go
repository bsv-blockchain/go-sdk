package wallet

import (
	"context"
	"log/slog"
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/logging"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ensure that TestWallet is implementing wallet.Interface
var _ Interface = &TestWallet{}

// TestWallet is a testing implementation of a wallet used in tests.
// It includes mock handlers for various cryptographic and identity-related operations.
// By default, it implements wallet.Interface methods using wallet.CompletedProtoWallet.
//
// Method behavior can be overridden using On<MethodName>() method that returns MockWalletMethods object.
// The MockWalletMethods object provides following methods to override behavior:
//   - ReturnSuccess(result) - sets successful response
//   - ReturnError(err) - sets error response
//   - Expect(func) - adds expectations that will be checked when method is called
//
// NOTE: For applying checks from Expect method, one of Return functions (ReturnSuccess, ReturnError, Return)
// must be called.
//
// Example:
//
//	// Override GetPublicKey to return success
//	wallet.OnGetPublicKey().ReturnSuccess(&GetPublicKeyResult{
//	    PublicKey: []byte("test-key"),
//	})
//
//	// Override GetPublicKey to return error
//	wallet.OnGetPublicKey().ReturnError(errors.New("test error"))
//
//	// Override GetPublicKey with expectations
//	wallet.OnGetPublicKey().
//	    Expect(func(ctx context.Context, args GetPublicKeyArgs, originator string) {
//	        assert.Equal(t, "test-key", args.Key)
//	    }).
//	    ReturnSuccess(&GetPublicKeyResult{
//	        PublicKey: []byte("test-key"),
//	    })
type TestWallet struct {

	// Name represents the wallet owner's name.
	// It is useful for debugging to distinguish between multiple wallets participating in communication.
	// By default, it is set to the identity key.
	Name string

	t                  testing.TB
	expectedOriginator string

	// Function implementations for methods needed by identity client tests
	getPublicKeyHandler                 func(ctx context.Context, args GetPublicKeyArgs, originator string) (*GetPublicKeyResult, error)
	encryptHandler                      func(ctx context.Context, args EncryptArgs, originator string) (*EncryptResult, error)
	decryptHandler                      func(ctx context.Context, args DecryptArgs, originator string) (*DecryptResult, error)
	createHMACHandler                   func(ctx context.Context, args CreateHMACArgs, originator string) (*CreateHMACResult, error)
	verifyHMACHandler                   func(ctx context.Context, args VerifyHMACArgs, originator string) (*VerifyHMACResult, error)
	createSignatureHandler              func(ctx context.Context, args CreateSignatureArgs, originator string) (*CreateSignatureResult, error)
	verifySignatureHandler              func(ctx context.Context, args VerifySignatureArgs, originator string) (*VerifySignatureResult, error)
	createActionHandler                 func(ctx context.Context, args CreateActionArgs, originator string) (*CreateActionResult, error)
	signActionHandler                   func(ctx context.Context, args SignActionArgs, originator string) (*SignActionResult, error)
	abortActionHandler                  func(ctx context.Context, args AbortActionArgs, originator string) (*AbortActionResult, error)
	listActionsHandler                  func(ctx context.Context, args ListActionsArgs, originator string) (*ListActionsResult, error)
	internalizeActionHandler            func(ctx context.Context, args InternalizeActionArgs, originator string) (*InternalizeActionResult, error)
	listOutputsHandler                  func(ctx context.Context, args ListOutputsArgs, originator string) (*ListOutputsResult, error)
	relinquishOutputHandler             func(ctx context.Context, args RelinquishOutputArgs, originator string) (*RelinquishOutputResult, error)
	revealCounterpartyKeyLinkageHandler func(ctx context.Context, args RevealCounterpartyKeyLinkageArgs, originator string) (*RevealCounterpartyKeyLinkageResult, error)
	revealSpecificKeyLinkageHandler     func(ctx context.Context, args RevealSpecificKeyLinkageArgs, originator string) (*RevealSpecificKeyLinkageResult, error)
	acquireCertificateHandler           func(ctx context.Context, args AcquireCertificateArgs, originator string) (*Certificate, error)
	listCertificatesHandler             func(ctx context.Context, args ListCertificatesArgs, originator string) (*ListCertificatesResult, error)
	proveCertificateHandler             func(ctx context.Context, args ProveCertificateArgs, originator string) (*ProveCertificateResult, error)
	relinquishCertificateHandler        func(ctx context.Context, args RelinquishCertificateArgs, originator string) (*RelinquishCertificateResult, error)
	discoverByIdentityKeyHandler        func(ctx context.Context, args DiscoverByIdentityKeyArgs, originator string) (*DiscoverCertificatesResult, error)
	discoverByAttributesHandler         func(ctx context.Context, args DiscoverByAttributesArgs, originator string) (*DiscoverCertificatesResult, error)
	isAuthenticatedHandler              func(ctx context.Context, args any, originator string) (*AuthenticatedResult, error)
	waitForAuthenticationHandler        func(ctx context.Context, args any, originator string) (*AuthenticatedResult, error)
	getHeightHandler                    func(ctx context.Context, args any, originator string) (*GetHeightResult, error)
	getHeaderForHeightHandler           func(ctx context.Context, args GetHeaderArgs, originator string) (*GetHeaderResult, error)
	getNetworkHandler                   func(ctx context.Context, args any, originator string) (*GetNetworkResult, error)
	getVersionHandler                   func(ctx context.Context, args any, originator string) (*GetVersionResult, error)

	proto              *CompletedProtoWallet
	logger             *slog.Logger
	globalExpectations []func(ctx context.Context, args any, originator string)
}

// NewTestWalletForRandomKey creates a new TestWallet with a randomly generated private key.
// This is a convenience function for tests that don't need a specific key.
// It internally calls NewTestWallet with the generated key.
func NewTestWalletForRandomKey(t testing.TB) *TestWallet {
	key, err := ec.NewPrivateKey()
	require.NoError(t, err, "Failed to create random key")

	return NewTestWallet(t, key)
}

// NewTestWallet creates a new TestWallet with the provided private key source.
// It accepts any type that implements the PrivateKeySource interface.
// The created TestWallet uses a CompletedProtoWallet internally to implement
// the wallet.Interface methods.
func NewTestWallet[KeySource PrivateKeySource](t testing.TB, keySource KeySource) *TestWallet {
	t.Helper()

	privKey, err := ToPrivateKey(keySource)
	require.NoError(t, err, "Invalid key source used for TestWallet creation")

	proto, err := NewCompletedProtoWallet(privKey)
	require.NoError(t, err, "Cannot create CompletedProtoWallet")

	return &TestWallet{
		t:      t,
		logger: logging.NewTestLogger(t),
		proto:  proto,
	}
}

// MockWalletMethods is used to configure mock behavior for TestWallet methods.
// It provides a fluent API for setting up expectations and return values for wallet method calls.
type MockWalletMethods[A, R any] struct {
	t            testing.TB
	setHandler   func(handler func(ctx context.Context, args A, originator string) (*R, error))
	expectations []func(ctx context.Context, args A, originator string)
}

// ExpectOriginator adds an expectation that the originator parameter passed to the wallet method
// matches the expected value. This is a convenience method that wraps Expect.
// Returns the MockWalletMethods instance for method chaining.
func (m *MockWalletMethods[A, R]) ExpectOriginator(expectedOriginator string) *MockWalletMethods[A, R] {
	m.t.Helper()
	m.Expect(func(ctx context.Context, args A, originator string) {
		assert.Equal(m.t, expectedOriginator, originator)
	})
	return m
}

// Expect adds a custom expectation function that will be called when the wallet method is invoked.
// The expectation function can perform assertions on the context, arguments, and originator.
// Multiple expectations can be added and they will all be checked in order.
// Returns the MockWalletMethods instance for method chaining.
func (m *MockWalletMethods[A, R]) Expect(expectations func(ctx context.Context, args A, originator string)) *MockWalletMethods[A, R] {
	m.t.Helper()
	m.expectations = append(m.expectations, expectations)
	return m
}

// ReturnSuccess configures the mock to return a successful result when the wallet method is called.
// This is a convenience method that calls Return with a nil error.
// After calling this method, any expectations added with Expect will be checked when the method is called.
func (m *MockWalletMethods[A, R]) ReturnSuccess(result *R) {
	m.Return(result, nil)
}

// ReturnError configures the mock to return an error when the wallet method is called.
// This is a convenience method that calls Return with a nil result.
// After calling this method, any expectations added with Expect will be checked when the method is called.
func (m *MockWalletMethods[A, R]) ReturnError(err error) {
	m.Return(nil, err)
}

// Return configures the mock to return the specified result and error when the wallet method is called.
// It also sets up the handler to check any expectations that were added with Expect.
// This is the core method that ReturnSuccess and ReturnError use internally.
func (m *MockWalletMethods[A, R]) Return(result *R, err error) {
	m.Do(func(ctx context.Context, args A, originator string) (*R, error) {
		for _, expectation := range m.expectations {
			expectation(ctx, args, originator)
		}
		return result, err
	})
}

// Reset removes any configured handler for the wallet method.
// After calling Reset, the method will use the default implementation from CompletedProtoWallet.
func (m *MockWalletMethods[A, R]) Reset() {
	m.Do(nil)
}

// Do sets a custom handler function for the wallet method.
// This is a low-level method that allows complete control over the method's behavior.
// The handler function receives the context, arguments, and originator, and should return a result and error.
// If handler is nil, any previously set handler is removed.
func (m *MockWalletMethods[A, R]) Do(handler func(ctx context.Context, args A, originator string) (*R, error)) {
	m.setHandler(handler)
}

// ExpectOriginator adds a global expectation that the originator parameter passed to any wallet method
// matches the expected value. This is useful when you want to verify the originator for all method calls
// without having to set it individually for each method.
func (m *TestWallet) ExpectOriginator(expectedOriginator string) {
	m.globalExpectations = append(m.globalExpectations, func(ctx context.Context, args any, originator string) {
		assert.Equal(m.t, expectedOriginator, originator)
	})
}

func (m *TestWallet) checkExpectations(ctx context.Context, args any, originator string) {
	if m.globalExpectations != nil {
		for _, expectation := range m.globalExpectations {
			expectation(ctx, args, originator)
		}
	}
}

// OnGetPublicKey returns a MockWalletMethods object that can be used to configure the behavior
// of the GetPublicKey method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnGetPublicKey() *MockWalletMethods[GetPublicKeyArgs, GetPublicKeyResult] {
	return &MockWalletMethods[GetPublicKeyArgs, GetPublicKeyResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args GetPublicKeyArgs, originator string) (*GetPublicKeyResult, error)) {
			m.getPublicKeyHandler = handler
		},
	}
}

func (m *TestWallet) GetPublicKey(ctx context.Context, args GetPublicKeyArgs, originator string) (*GetPublicKeyResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "GetPublicKey", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.getPublicKeyHandler != nil {
		return m.getPublicKeyHandler(ctx, args, originator)
	}
	return m.proto.GetPublicKey(ctx, args, originator)
}

// OnEncrypt returns a MockWalletMethods object that can be used to configure the behavior
// of the Encrypt method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnEncrypt() *MockWalletMethods[EncryptArgs, EncryptResult] {
	return &MockWalletMethods[EncryptArgs, EncryptResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args EncryptArgs, originator string) (*EncryptResult, error)) {
			m.encryptHandler = handler
		},
	}
}

func (m *TestWallet) Encrypt(ctx context.Context, args EncryptArgs, originator string) (*EncryptResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "Encrypt", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.encryptHandler != nil {
		return m.encryptHandler(ctx, args, originator)
	}
	return m.proto.Encrypt(ctx, args, originator)
}

// OnDecrypt returns a MockWalletMethods object that can be used to configure the behavior
// of the Decrypt method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnDecrypt() *MockWalletMethods[DecryptArgs, DecryptResult] {
	return &MockWalletMethods[DecryptArgs, DecryptResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args DecryptArgs, originator string) (*DecryptResult, error)) {
			m.decryptHandler = handler
		},
	}
}

func (m *TestWallet) Decrypt(ctx context.Context, args DecryptArgs, originator string) (*DecryptResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "Decrypt", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.decryptHandler != nil {
		return m.decryptHandler(ctx, args, originator)
	}
	return m.proto.Decrypt(ctx, args, originator)
}

// OnCreateHMAC returns a MockWalletMethods object that can be used to configure the behavior
// of the CreateHMAC method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnCreateHMAC() *MockWalletMethods[CreateHMACArgs, CreateHMACResult] {
	return &MockWalletMethods[CreateHMACArgs, CreateHMACResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args CreateHMACArgs, originator string) (*CreateHMACResult, error)) {
			m.createHMACHandler = handler
		},
	}
}

func (m *TestWallet) CreateHMAC(ctx context.Context, args CreateHMACArgs, originator string) (*CreateHMACResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "CreateHMAC", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.createHMACHandler != nil {
		return m.createHMACHandler(ctx, args, originator)
	}
	return m.proto.CreateHMAC(ctx, args, originator)
}

// OnVerifyHMAC returns a MockWalletMethods object that can be used to configure the behavior
// of the VerifyHMAC method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnVerifyHMAC() *MockWalletMethods[VerifyHMACArgs, VerifyHMACResult] {
	return &MockWalletMethods[VerifyHMACArgs, VerifyHMACResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args VerifyHMACArgs, originator string) (*VerifyHMACResult, error)) {
			m.verifyHMACHandler = handler
		},
	}
}

func (m *TestWallet) VerifyHMAC(ctx context.Context, args VerifyHMACArgs, originator string) (*VerifyHMACResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "VerifyHMAC", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.verifyHMACHandler != nil {
		return m.verifyHMACHandler(ctx, args, originator)
	}
	return m.proto.VerifyHMAC(ctx, args, originator)
}

// OnCreateSignature returns a MockWalletMethods object that can be used to configure the behavior
// of the CreateSignature method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnCreateSignature() *MockWalletMethods[CreateSignatureArgs, CreateSignatureResult] {
	return &MockWalletMethods[CreateSignatureArgs, CreateSignatureResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args CreateSignatureArgs, originator string) (*CreateSignatureResult, error)) {
			m.createSignatureHandler = handler
		},
	}
}

func (m *TestWallet) CreateSignature(ctx context.Context, args CreateSignatureArgs, originator string) (*CreateSignatureResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "CreateSignature", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.createSignatureHandler != nil {
		return m.createSignatureHandler(ctx, args, originator)
	}
	return m.proto.CreateSignature(ctx, args, originator)
}

// OnVerifySignature returns a MockWalletMethods object that can be used to configure the behavior
// of the VerifySignature method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnVerifySignature() *MockWalletMethods[VerifySignatureArgs, VerifySignatureResult] {
	return &MockWalletMethods[VerifySignatureArgs, VerifySignatureResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args VerifySignatureArgs, originator string) (*VerifySignatureResult, error)) {
			m.verifySignatureHandler = handler
		},
	}
}

func (m *TestWallet) VerifySignature(ctx context.Context, args VerifySignatureArgs, originator string) (*VerifySignatureResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "VerifySignature", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.verifySignatureHandler != nil {
		return m.verifySignatureHandler(ctx, args, originator)
	}
	return m.proto.VerifySignature(ctx, args, originator)
}

// OnCreateAction returns a MockWalletMethods object that can be used to configure the behavior
// of the CreateAction method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnCreateAction() *MockWalletMethods[CreateActionArgs, CreateActionResult] {
	return &MockWalletMethods[CreateActionArgs, CreateActionResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args CreateActionArgs, originator string) (*CreateActionResult, error)) {
			m.createActionHandler = handler
		},
	}
}

func (m *TestWallet) CreateAction(ctx context.Context, args CreateActionArgs, originator string) (*CreateActionResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "CreateAction", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.createActionHandler != nil {
		return m.createActionHandler(ctx, args, originator)
	}
	return m.proto.CreateAction(ctx, args, originator)
}

// OnSignAction returns a MockWalletMethods object that can be used to configure the behavior
// of the SignAction method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnSignAction() *MockWalletMethods[SignActionArgs, SignActionResult] {
	return &MockWalletMethods[SignActionArgs, SignActionResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args SignActionArgs, originator string) (*SignActionResult, error)) {
			m.signActionHandler = handler
		},
	}
}

func (m *TestWallet) SignAction(ctx context.Context, args SignActionArgs, originator string) (*SignActionResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "SignAction", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.signActionHandler != nil {
		return m.signActionHandler(ctx, args, originator)
	}
	return m.proto.SignAction(ctx, args, originator)
}

// OnAbortAction returns a MockWalletMethods object that can be used to configure the behavior
// of the AbortAction method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnAbortAction() *MockWalletMethods[AbortActionArgs, AbortActionResult] {
	return &MockWalletMethods[AbortActionArgs, AbortActionResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args AbortActionArgs, originator string) (*AbortActionResult, error)) {
			m.abortActionHandler = handler
		},
	}
}

func (m *TestWallet) AbortAction(ctx context.Context, args AbortActionArgs, originator string) (*AbortActionResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "AbortAction", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.abortActionHandler != nil {
		return m.abortActionHandler(ctx, args, originator)
	}
	return m.proto.AbortAction(ctx, args, originator)
}

// OnListActions returns a MockWalletMethods object that can be used to configure the behavior
// of the ListActions method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnListActions() *MockWalletMethods[ListActionsArgs, ListActionsResult] {
	return &MockWalletMethods[ListActionsArgs, ListActionsResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args ListActionsArgs, originator string) (*ListActionsResult, error)) {
			m.listActionsHandler = handler
		},
	}
}

func (m *TestWallet) ListActions(ctx context.Context, args ListActionsArgs, originator string) (*ListActionsResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "ListActions", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.listActionsHandler != nil {
		return m.listActionsHandler(ctx, args, originator)
	}
	return m.proto.ListActions(ctx, args, originator)
}

// OnInternalizeAction returns a MockWalletMethods object that can be used to configure the behavior
// of the InternalizeAction method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnInternalizeAction() *MockWalletMethods[InternalizeActionArgs, InternalizeActionResult] {
	return &MockWalletMethods[InternalizeActionArgs, InternalizeActionResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args InternalizeActionArgs, originator string) (*InternalizeActionResult, error)) {
			m.internalizeActionHandler = handler
		},
	}
}

func (m *TestWallet) InternalizeAction(ctx context.Context, args InternalizeActionArgs, originator string) (*InternalizeActionResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "InternalizeAction", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.internalizeActionHandler != nil {
		return m.internalizeActionHandler(ctx, args, originator)
	}
	return m.proto.InternalizeAction(ctx, args, originator)
}

// OnListOutputs returns a MockWalletMethods object that can be used to configure the behavior
// of the ListOutputs method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnListOutputs() *MockWalletMethods[ListOutputsArgs, ListOutputsResult] {
	return &MockWalletMethods[ListOutputsArgs, ListOutputsResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args ListOutputsArgs, originator string) (*ListOutputsResult, error)) {
			m.listOutputsHandler = handler
		},
	}
}

func (m *TestWallet) ListOutputs(ctx context.Context, args ListOutputsArgs, originator string) (*ListOutputsResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "ListOutputs", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.listOutputsHandler != nil {
		return m.listOutputsHandler(ctx, args, originator)
	}
	return m.proto.ListOutputs(ctx, args, originator)
}

// OnRelinquishOutput returns a MockWalletMethods object that can be used to configure the behavior
// of the RelinquishOutput method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnRelinquishOutput() *MockWalletMethods[RelinquishOutputArgs, RelinquishOutputResult] {
	return &MockWalletMethods[RelinquishOutputArgs, RelinquishOutputResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args RelinquishOutputArgs, originator string) (*RelinquishOutputResult, error)) {
			m.relinquishOutputHandler = handler
		},
	}
}

func (m *TestWallet) RelinquishOutput(ctx context.Context, args RelinquishOutputArgs, originator string) (*RelinquishOutputResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "RelinquishOutput", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.relinquishOutputHandler != nil {
		return m.relinquishOutputHandler(ctx, args, originator)
	}
	return m.proto.RelinquishOutput(ctx, args, originator)
}

// OnRevealCounterpartyKeyLinkage returns a MockWalletMethods object that can be used to configure the behavior
// of the RevealCounterpartyKeyLinkage method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnRevealCounterpartyKeyLinkage() *MockWalletMethods[RevealCounterpartyKeyLinkageArgs, RevealCounterpartyKeyLinkageResult] {
	return &MockWalletMethods[RevealCounterpartyKeyLinkageArgs, RevealCounterpartyKeyLinkageResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args RevealCounterpartyKeyLinkageArgs, originator string) (*RevealCounterpartyKeyLinkageResult, error)) {
			m.revealCounterpartyKeyLinkageHandler = handler
		},
	}
}

func (m *TestWallet) RevealCounterpartyKeyLinkage(ctx context.Context, args RevealCounterpartyKeyLinkageArgs, originator string) (*RevealCounterpartyKeyLinkageResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "RevealCounterpartyKeyLinkage", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.revealCounterpartyKeyLinkageHandler != nil {
		return m.revealCounterpartyKeyLinkageHandler(ctx, args, originator)
	}
	return m.proto.RevealCounterpartyKeyLinkage(ctx, args, originator)
}

// OnRevealSpecificKeyLinkage returns a MockWalletMethods object that can be used to configure the behavior
// of the RevealSpecificKeyLinkage method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnRevealSpecificKeyLinkage() *MockWalletMethods[RevealSpecificKeyLinkageArgs, RevealSpecificKeyLinkageResult] {
	return &MockWalletMethods[RevealSpecificKeyLinkageArgs, RevealSpecificKeyLinkageResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args RevealSpecificKeyLinkageArgs, originator string) (*RevealSpecificKeyLinkageResult, error)) {
			m.revealSpecificKeyLinkageHandler = handler
		},
	}
}

func (m *TestWallet) RevealSpecificKeyLinkage(ctx context.Context, args RevealSpecificKeyLinkageArgs, originator string) (*RevealSpecificKeyLinkageResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "RevealSpecificKeyLinkage", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.revealSpecificKeyLinkageHandler != nil {
		return m.revealSpecificKeyLinkageHandler(ctx, args, originator)
	}
	return m.proto.RevealSpecificKeyLinkage(ctx, args, originator)
}

// OnAcquireCertificate returns a MockWalletMethods object that can be used to configure the behavior
// of the AcquireCertificate method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnAcquireCertificate() *MockWalletMethods[AcquireCertificateArgs, Certificate] {
	return &MockWalletMethods[AcquireCertificateArgs, Certificate]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args AcquireCertificateArgs, originator string) (*Certificate, error)) {
			m.acquireCertificateHandler = handler
		},
	}
}

func (m *TestWallet) AcquireCertificate(ctx context.Context, args AcquireCertificateArgs, originator string) (*Certificate, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "AcquireCertificate", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.acquireCertificateHandler != nil {
		return m.acquireCertificateHandler(ctx, args, originator)
	}
	return m.proto.AcquireCertificate(ctx, args, originator)
}

// OnListCertificates returns a MockWalletMethods object that can be used to configure the behavior
// of the ListCertificates method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnListCertificates() *MockWalletMethods[ListCertificatesArgs, ListCertificatesResult] {
	return &MockWalletMethods[ListCertificatesArgs, ListCertificatesResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args ListCertificatesArgs, originator string) (*ListCertificatesResult, error)) {
			m.listCertificatesHandler = handler
		},
	}
}

func (m *TestWallet) ListCertificates(ctx context.Context, args ListCertificatesArgs, originator string) (*ListCertificatesResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "ListCertificates", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.listCertificatesHandler != nil {
		return m.listCertificatesHandler(ctx, args, originator)
	}
	return m.proto.ListCertificates(ctx, args, originator)
}

// OnProveCertificate returns a MockWalletMethods object that can be used to configure the behavior
// of the ProveCertificate method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnProveCertificate() *MockWalletMethods[ProveCertificateArgs, ProveCertificateResult] {
	return &MockWalletMethods[ProveCertificateArgs, ProveCertificateResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args ProveCertificateArgs, originator string) (*ProveCertificateResult, error)) {
			m.proveCertificateHandler = handler
		},
	}
}

func (m *TestWallet) ProveCertificate(ctx context.Context, args ProveCertificateArgs, originator string) (*ProveCertificateResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "ProveCertificate", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.proveCertificateHandler != nil {
		return m.proveCertificateHandler(ctx, args, originator)
	}
	return m.proto.ProveCertificate(ctx, args, originator)
}

// OnRelinquishCertificate returns a MockWalletMethods object that can be used to configure the behavior
// of the RelinquishCertificate method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnRelinquishCertificate() *MockWalletMethods[RelinquishCertificateArgs, RelinquishCertificateResult] {
	return &MockWalletMethods[RelinquishCertificateArgs, RelinquishCertificateResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args RelinquishCertificateArgs, originator string) (*RelinquishCertificateResult, error)) {
			m.relinquishCertificateHandler = handler
		},
	}
}

func (m *TestWallet) RelinquishCertificate(ctx context.Context, args RelinquishCertificateArgs, originator string) (*RelinquishCertificateResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "RelinquishCertificate", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.relinquishCertificateHandler != nil {
		return m.relinquishCertificateHandler(ctx, args, originator)
	}
	return m.proto.RelinquishCertificate(ctx, args, originator)
}

// OnDiscoverByIdentityKey returns a MockWalletMethods object that can be used to configure the behavior
// of the DiscoverByIdentityKey method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnDiscoverByIdentityKey() *MockWalletMethods[DiscoverByIdentityKeyArgs, DiscoverCertificatesResult] {
	return &MockWalletMethods[DiscoverByIdentityKeyArgs, DiscoverCertificatesResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args DiscoverByIdentityKeyArgs, originator string) (*DiscoverCertificatesResult, error)) {
			m.discoverByIdentityKeyHandler = handler
		},
	}
}

func (m *TestWallet) DiscoverByIdentityKey(ctx context.Context, args DiscoverByIdentityKeyArgs, originator string) (*DiscoverCertificatesResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "DiscoverByIdentityKey", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.discoverByIdentityKeyHandler != nil {
		return m.discoverByIdentityKeyHandler(ctx, args, originator)
	}
	return m.proto.DiscoverByIdentityKey(ctx, args, originator)
}

// OnDiscoverByAttributes returns a MockWalletMethods object that can be used to configure the behavior
// of the DiscoverByAttributes method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnDiscoverByAttributes() *MockWalletMethods[DiscoverByAttributesArgs, DiscoverCertificatesResult] {
	return &MockWalletMethods[DiscoverByAttributesArgs, DiscoverCertificatesResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args DiscoverByAttributesArgs, originator string) (*DiscoverCertificatesResult, error)) {
			m.discoverByAttributesHandler = handler
		},
	}
}

func (m *TestWallet) DiscoverByAttributes(ctx context.Context, args DiscoverByAttributesArgs, originator string) (*DiscoverCertificatesResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "DiscoverByAttributes", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.discoverByAttributesHandler != nil {
		return m.discoverByAttributesHandler(ctx, args, originator)
	}
	return m.proto.DiscoverByAttributes(ctx, args, originator)
}

// OnIsAuthenticated returns a MockWalletMethods object that can be used to configure the behavior
// of the IsAuthenticated method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnIsAuthenticated() *MockWalletMethods[any, AuthenticatedResult] {
	return &MockWalletMethods[any, AuthenticatedResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args any, originator string) (*AuthenticatedResult, error)) {
			m.isAuthenticatedHandler = handler
		},
	}
}

func (m *TestWallet) IsAuthenticated(ctx context.Context, args any, originator string) (*AuthenticatedResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "IsAuthenticated", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.isAuthenticatedHandler != nil {
		return m.isAuthenticatedHandler(ctx, args, originator)
	}
	return m.proto.IsAuthenticated(ctx, args, originator)
}

// OnWaitForAuthentication returns a MockWalletMethods object that can be used to configure the behavior
// of the WaitForAuthentication method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnWaitForAuthentication() *MockWalletMethods[any, AuthenticatedResult] {
	return &MockWalletMethods[any, AuthenticatedResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args any, originator string) (*AuthenticatedResult, error)) {
			m.waitForAuthenticationHandler = handler
		},
	}
}

func (m *TestWallet) WaitForAuthentication(ctx context.Context, args any, originator string) (*AuthenticatedResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "WaitForAuthentication", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.waitForAuthenticationHandler != nil {
		return m.waitForAuthenticationHandler(ctx, args, originator)
	}
	return m.proto.WaitForAuthentication(ctx, args, originator)
}

// OnGetHeight returns a MockWalletMethods object that can be used to configure the behavior
// of the GetHeight method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnGetHeight() *MockWalletMethods[any, GetHeightResult] {
	return &MockWalletMethods[any, GetHeightResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args any, originator string) (*GetHeightResult, error)) {
			m.getHeightHandler = handler
		},
	}
}

func (m *TestWallet) GetHeight(ctx context.Context, args any, originator string) (*GetHeightResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "GetHeight", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.getHeightHandler != nil {
		return m.getHeightHandler(ctx, args, originator)
	}
	return m.proto.GetHeight(ctx, args, originator)
}

// OnGetHeaderForHeight returns a MockWalletMethods object that can be used to configure the behavior
// of the GetHeaderForHeight method. This allows overriding the default implementation with custom
// behavior for testing purposes.
func (m *TestWallet) OnGetHeaderForHeight() *MockWalletMethods[GetHeaderArgs, GetHeaderResult] {
	return &MockWalletMethods[GetHeaderArgs, GetHeaderResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args GetHeaderArgs, originator string) (*GetHeaderResult, error)) {
			m.getHeaderForHeightHandler = handler
		},
	}
}

func (m *TestWallet) GetHeaderForHeight(ctx context.Context, args GetHeaderArgs, originator string) (*GetHeaderResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "GetHeaderForHeight", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.getHeaderForHeightHandler != nil {
		return m.getHeaderForHeightHandler(ctx, args, originator)
	}
	return m.proto.GetHeaderForHeight(ctx, args, originator)
}

func (m *TestWallet) OnGetNetwork() *MockWalletMethods[any, GetNetworkResult] {
	return &MockWalletMethods[any, GetNetworkResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args any, originator string) (*GetNetworkResult, error)) {
			m.getNetworkHandler = handler
		},
	}
}

func (m *TestWallet) GetNetwork(ctx context.Context, args any, originator string) (*GetNetworkResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "GetNetwork", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.getNetworkHandler != nil {
		return m.getNetworkHandler(ctx, args, originator)
	}
	return m.proto.GetNetwork(ctx, args, originator)
}

func (m *TestWallet) OnGetVersion() *MockWalletMethods[any, GetVersionResult] {
	return &MockWalletMethods[any, GetVersionResult]{
		t: m.t,
		setHandler: func(handler func(ctx context.Context, args any, originator string) (*GetVersionResult, error)) {
			m.getVersionHandler = handler
		},
	}
}

func (m *TestWallet) GetVersion(ctx context.Context, args any, originator string) (*GetVersionResult, error) {
	m.logger.DebugContext(ctx, "Wallet method called", "method", "GetVersion", "args", args, "originator", originator)

	m.checkExpectations(ctx, args, originator)

	if m.getVersionHandler != nil {
		return m.getVersionHandler(ctx, args, originator)
	}
	return m.proto.GetVersion(ctx, args, originator)
}
