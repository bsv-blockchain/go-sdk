//go:build cgo && !ios && !android && (darwin || linux) && (amd64 || arm64)

package bdk

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"

	bdkscript "github.com/bitcoin-sv/bdk/module/gobdk/script"
	bdksecp256k1 "github.com/bitcoin-sv/bdk/module/gobdk/secp256k1"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

var (
	// ErrNilTransaction is returned when an operation receives a nil transaction.
	ErrNilTransaction = errors.New("bdk: transaction is nil")
	// ErrNilValidator is returned when an operation receives a nil validator.
	ErrNilValidator = errors.New("bdk: validator is nil")
	// ErrNilBatch is returned when an operation receives a nil validation batch.
	ErrNilBatch = errors.New("bdk: validation batch is nil")
	// ErrUnsupportedNetwork is returned when GoBDK does not recognize a network name.
	ErrUnsupportedNetwork = errors.New("bdk: unsupported network")
	// ErrUTXOHeightCount is returned when there is not one UTXO height per input.
	ErrUTXOHeightCount = errors.New("bdk: UTXO height count does not match input count")
	// ErrCustomFlagCount is returned when custom flags are neither empty nor one per input.
	ErrCustomFlagCount = errors.New("bdk: custom flag count does not match input count")
)

// Validator adapts transaction.Transaction values to a GoBDK TxValidator.
type Validator struct {
	native *bdkscript.TxValidator
}

// NewValidator creates a GoBDK transaction validator for network. GoBDK
// recognizes main, test, regtest, stn, teratestnet, and tstn.
func NewValidator(network string) (*Validator, error) {
	native := bdkscript.NewTxValidator(network)
	if native == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedNetwork, network)
	}
	return &Validator{native: native}, nil
}

// WrapValidator adapts an existing, potentially policy-configured GoBDK
// validator.
func WrapValidator(native *bdkscript.TxValidator) (*Validator, error) {
	if native == nil {
		return nil, ErrNilValidator
	}
	return &Validator{native: native}, nil
}

// Native returns the underlying GoBDK validator. It can be used to configure
// GoBDK policy settings not duplicated by this adapter.
func (v *Validator) Native() *bdkscript.TxValidator {
	if v == nil {
		return nil
	}
	return v.native
}

// ValidateTransaction runs GoBDK's transaction-level and script validation.
// Setting consensus to false applies policy and consensus checks; true applies
// consensus checks only.
func (v *Validator) ValidateTransaction(tx *transaction.Transaction, utxoHeights []int32, blockHeight int32, consensus bool) error {
	if err := v.valid(); err != nil {
		return err
	}
	extendedTx, err := validationArguments(tx, utxoHeights, nil)
	if err != nil {
		return err
	}
	return v.native.ValidateTransaction(extendedTx, utxoHeights, blockHeight, consensus)
}

// VerifyScript verifies every input script with flags calculated by GoBDK.
func (v *Validator) VerifyScript(tx *transaction.Transaction, utxoHeights []int32, blockHeight int32, consensus bool) error {
	if err := v.valid(); err != nil {
		return err
	}
	extendedTx, err := validationArguments(tx, utxoHeights, nil)
	if err != nil {
		return err
	}
	return v.native.VerifyScript(extendedTx, utxoHeights, blockHeight, consensus)
}

// VerifyScriptWithCustomFlags verifies every input script using customFlags.
// customFlags may be empty or must contain one entry per transaction input.
func (v *Validator) VerifyScriptWithCustomFlags(tx *transaction.Transaction, utxoHeights []int32, blockHeight int32, consensus bool, customFlags []uint32) error {
	if err := v.valid(); err != nil {
		return err
	}
	extendedTx, err := validationArguments(tx, utxoHeights, customFlags)
	if err != nil {
		return err
	}
	return v.native.VerifyScriptWithCustomFlags(extendedTx, utxoHeights, blockHeight, consensus, customFlags)
}

// GetSigOpCount returns GoBDK's signature-operation count for tx.
func (v *Validator) GetSigOpCount(tx *transaction.Transaction, utxoHeights []int32, blockHeight int32, countP2SHSigOps bool, consensus bool) (uint64, error) {
	if err := v.valid(); err != nil {
		return 0, err
	}
	extendedTx, err := validationArguments(tx, utxoHeights, nil)
	if err != nil {
		return 0, err
	}
	return v.native.GetSigOpCount(extendedTx, utxoHeights, blockHeight, countP2SHSigOps, consensus)
}

func (v *Validator) valid() error {
	if v == nil || v.native == nil {
		return ErrNilValidator
	}
	return nil
}

func validationArguments(tx *transaction.Transaction, utxoHeights []int32, customFlags []uint32) ([]byte, error) {
	if tx == nil {
		return nil, ErrNilTransaction
	}
	inputCount := len(tx.Inputs)
	if len(utxoHeights) != inputCount {
		return nil, fmt.Errorf("%w: got %d heights for %d inputs", ErrUTXOHeightCount, len(utxoHeights), inputCount)
	}
	if len(customFlags) != 0 && len(customFlags) != inputCount {
		return nil, fmt.Errorf("%w: got %d flags for %d inputs", ErrCustomFlagCount, len(customFlags), inputCount)
	}
	extendedTx, err := tx.EF()
	if err != nil {
		return nil, err
	}
	return extendedTx, nil
}

// ValidateBatch adapts a GoBDK validation batch to go-sdk transactions.
//
// A batch is not safe for concurrent use. All Add calls and the corresponding
// Validator.ValidateBatch call must run on the same goroutine unless the caller
// provides external synchronization.
type ValidateBatch struct {
	native          *bdkscript.ValidateBatch
	extendedTxs     [][]byte
	utxoHeightLists [][]int32
	pinner          *runtime.Pinner
}

// NewValidateBatch creates a validation batch. An optional positive capacity
// preallocates the underlying GoBDK batch.
func NewValidateBatch(capacity ...int) *ValidateBatch {
	native := bdkscript.NewValidateBatch(capacity...)
	if native == nil {
		return nil
	}
	batch := &ValidateBatch{
		native: native,
		pinner: new(runtime.Pinner),
	}
	runtime.SetFinalizer(batch, finalizeValidateBatch)
	return batch
}

func finalizeValidateBatch(batch *ValidateBatch) {
	batch.Clear()
}

// Add serializes and adds tx to the batch. The adapter pins and retains the
// serialized transaction and a private copy of the heights until Clear is
// called because GoBDK retains pointers to their memory while processing the
// batch.
func (b *ValidateBatch) Add(tx *transaction.Transaction, utxoHeights []int32, blockHeight int32, consensus bool) error {
	if b == nil || b.native == nil {
		return ErrNilBatch
	}
	extendedTx, err := validationArguments(tx, utxoHeights, nil)
	if err != nil {
		return err
	}
	heights := append([]int32(nil), utxoHeights...)
	if len(extendedTx) > 0 {
		b.pinner.Pin(&extendedTx[0])
	}
	if len(heights) > 0 {
		b.pinner.Pin(&heights[0])
	}
	b.extendedTxs = append(b.extendedTxs, extendedTx)
	b.utxoHeightLists = append(b.utxoHeightLists, heights)
	b.native.Add(extendedTx, heights, blockHeight, consensus)
	runtime.KeepAlive(b)
	return nil
}

// ValidateBatch validates every entry and returns one error per entry in
// insertion order. A nil entry represents successful validation.
func (v *Validator) ValidateBatch(batch *ValidateBatch) ([]error, error) {
	if err := v.valid(); err != nil {
		return nil, err
	}
	if batch == nil || batch.native == nil {
		return nil, ErrNilBatch
	}
	results := v.native.ValidateBatch(batch.native)
	runtime.KeepAlive(batch)
	return results, nil
}

// Clear removes all entries, unpins their Go buffers, and releases them.
func (b *ValidateBatch) Clear() {
	if b == nil || b.native == nil {
		return
	}
	// GoBDK stores spans into the pinned buffers. Clear the native spans before
	// making the Go memory movable and collectible again.
	b.native.Clear()
	b.pinner.Unpin()
	b.extendedTxs = nil
	b.utxoHeightLists = nil
}

// Size returns the number of entries in the batch.
func (b *ValidateBatch) Size() int {
	if b == nil || b.native == nil {
		return 0
	}
	return b.native.Size()
}

// Empty reports whether the batch contains no entries.
func (b *ValidateBatch) Empty() bool {
	return b == nil || b.native == nil || b.native.Empty()
}

// Reserve preallocates space for capacity entries.
func (b *ValidateBatch) Reserve(capacity int) {
	if b == nil || b.native == nil {
		return
	}
	b.native.Reserve(capacity)
}

// InstallSignatureBackend selects GoBDK's secp256k1 implementation for SDK
// ECDSA signature creation and verification. This includes direct EC calls,
// wallet and message signatures, transaction templates, OP_CHECKSIG, and
// OP_CHECKMULTISIG. The selection is process-wide and should normally be made
// during application startup.
func InstallSignatureBackend() {
	ec.InjectExternalSignerFn(signMessage)
	ec.InjectExternalVerifySignatureFn(verifySignature)
	interpreter.InjectExternalVerifySignatureFn(verifySignature)
}

// ResetSignatureBackend restores the SDK's built-in pure-Go signature creation
// and verification implementation.
func ResetSignatureBackend() {
	ec.InjectExternalSignerFn(nil)
	ec.InjectExternalVerifySignatureFn(nil)
	interpreter.InjectExternalVerifySignatureFn(nil)
}

func signMessage(message, privateKey []byte) ([]byte, error) {
	// Keep the safety check at this adapter boundary instead of relying on the
	// native dependency to reject a slice that is too short for a 32-byte read.
	if len(message) != sha256.Size {
		return nil, fmt.Errorf("bdk: message digest must be %d bytes: got %d", sha256.Size, len(message))
	}
	return bdksecp256k1.SignMessage(message, privateKey)
}

func verifySignature(message, signature, publicKey []byte) bool {
	// GoBDK's C API reads a 32-byte digest without checking the Go slice length.
	if len(message) != sha256.Size {
		return false
	}
	return bdksecp256k1.VerifySignature(message, signature, publicKey)
}
