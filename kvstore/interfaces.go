package kvstore

import (
	"context"
	"errors"

	"github.com/bsv-blockchain/go-sdk/v2/wallet"
)

// KVStoreInterface defines the interface for a key-value store
// backed by transaction outputs managed by a wallet.
type KVStoreInterface interface {
	// Get retrieves a value for the given key, or returns the defaultValue if not found.
	// If multiple values exist for the key, the most recent one is returned.
	// Returns ErrKeyNotFound if the key is not found and no defaultValue is provided (or behavior adjusted based on defaultValue).
	// Returns ErrCorruptedState if the data associated with the key is unreadable or invalid.
	// May return other errors related to wallet operations or context cancellation.
	Get(ctx context.Context, key string, defaultValue string) (string, error)

	// Set stores a value with the given key, returning the outpoint of the transaction output.
	// If the key already exists, the existing outputs are spent and a new one is created.
	// If multiple outputs exist with the same key, they are collapsed into a single output.
	// Returns ErrWalletOperationFailed if creating or signing the transaction fails.
	// May return other errors related to wallet operations (e.g., encryption) or context cancellation.
	Set(ctx context.Context, key string, value string) (string, error)

	// Remove deletes all values for the given key by spending the outputs.
	// Returns the transaction IDs of the removal transactions.
	// If no outputs are found for the key, returns an empty slice without error.
	// Returns ErrWalletOperationFailed if creating or signing the removal transaction fails.
	// May return other errors related to wallet operations or context cancellation.
	Remove(ctx context.Context, key string) ([]string, error)
}

// KVStoreConfig contains the configuration options for creating a new KVStore.
type KVStoreConfig struct {
	// Wallet is the wallet interface used to interact with the blockchain
	Wallet wallet.Interface

	// Context is the application-defined context for namespacing keys
	// This is used as the basket name for outputs
	Context string

	// Encrypt determines whether values should be encrypted before storage
	Encrypt bool

	// Originator is a string identifying the application using the KVStore
	Originator string
}

// Error definitions

// type kvStoreError struct {
// 	message string
// 	err     error // underlying error
// }

// func (e *kvStoreError) Error() string {
// 	if e.err != nil {
// 		return e.message + ": " + e.err.Error()
// 	}
// 	return e.message
// }

// func (e *kvStoreError) Unwrap() error {
// 	return e.err
// }

// func newError(message string, cause error) error {
// 	return &kvStoreError{message: message, err: cause}
// }

// Specific error types
var (
	ErrInvalidWallet     = errors.New("invalid wallet provided")
	ErrEmptyContext      = errors.New("context cannot be empty")
	ErrKeyNotFound       = errors.New("key not found")
	ErrCorruptedState    = errors.New("corrupted data state encountered")
	ErrWalletOperation   = errors.New("wallet operation failed")
	ErrTransactionCreate = errors.New("failed to create transaction")
	ErrTransactionSign   = errors.New("failed to sign transaction")
	ErrEncryption        = errors.New("encryption/decryption failed")
	ErrDataParsing       = errors.New("failed to parse data (BEEF, PushDrop, etc.)")
)

// NewLocalKVStoreOptions contains the configuration options for creating a new LocalKVStore.
type NewLocalKVStoreOptions struct {
	Wallet          wallet.Interface
	Originator      string
	Context         string
	RetentionPeriod uint32
	BasketName      string
	Encrypt         bool
}

// Error definitions for LocalKVStore options and operations.
var (
	ErrInvalidRetentionPeriod = errors.New("invalid retention period")
	ErrInvalidOriginator      = errors.New("invalid originator")
	ErrInvalidContext         = errors.New("invalid context")
	ErrInvalidBasketName      = errors.New("invalid basket name")
	ErrInvalidKey             = errors.New("invalid key")
	ErrInvalidValue           = errors.New("invalid value")
	ErrNotFound               = errors.New("key not found")
)

// DefaultPaymentAmount is the default satoshis to send for a key-value output.
const DefaultPaymentAmount = uint64(1)

// KeyValue represents a key-value pair.
type KeyValue struct {
	Key   string
	Value string
}

// Helper functions for creating wrapped errors (optional but can be useful)

// func WrapCorruptedState(cause error) error {
// 	return newError(ErrCorruptedState.Error(), cause)
// }

// func WrapWalletOperation(opName string, cause error) error {
// 	return newError(fmt.Sprintf("%s: %s", ErrWalletOperation.Error(), opName), cause)
// }

// func WrapEncryption(cause error) error {
// 	return newError(ErrEncryption.Error(), cause)
// }

// func WrapDataParsing(dataType string, cause error) error {
// 	return newError(fmt.Sprintf("%s: %s", ErrDataParsing.Error(), dataType), cause)
// }
