package wallet

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	transaction "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// SecurityLevel defines the access control level for wallet operations.
// It determines how strictly the wallet enforces user confirmation for operations.
type SecurityLevel int

var (
	SecurityLevelSilent                  SecurityLevel = 0
	SecurityLevelEveryApp                SecurityLevel = 1
	SecurityLevelEveryAppAndCounterparty SecurityLevel = 2
)

// WalletProtocol defines a protocol with its security level and name.
// The security level determines how strictly the wallet enforces user confirmation.
type WalletProtocol struct {
	SecurityLevel SecurityLevel
	Protocol      string
}

type CounterpartyType int

const (
	CounterpartyUninitialized CounterpartyType = 0
	CounterpartyTypeAnyone    CounterpartyType = 1
	CounterpartyTypeSelf      CounterpartyType = 2
	CounterpartyTypeOther     CounterpartyType = 3
)

// WalletCounterparty represents the other party in a cryptographic operation.
// It can be a specific public key, or one of the special values 'self' or 'anyone'.
type WalletCounterparty struct {
	Type         CounterpartyType
	Counterparty *ec.PublicKey
}

// Wallet provides cryptographic operations for a specific identity.
// It can encrypt/decrypt data, create/verify signatures, and manage keys.
type Wallet struct {
	privateKey *ec.PrivateKey
	publicKey  *ec.PublicKey
	keyDeriver *KeyDeriver
}

// NewWallet creates a new wallet instance using the provided private key.
// The private key serves as the root of trust for all cryptographic operations.
func NewWallet(privateKey *ec.PrivateKey) *Wallet {
	return &Wallet{
		privateKey: privateKey,
		publicKey:  privateKey.PubKey(),
		keyDeriver: NewKeyDeriver(privateKey),
	}
}

type EncryptionArgs struct {
	ProtocolID       WalletProtocol
	KeyID            string
	Counterparty     WalletCounterparty
	Privileged       bool
	PrivilegedReason string
	SeekPermission   bool
}

type EncryptArgs struct {
	EncryptionArgs
	Plaintext []byte
}

type DecryptArgs struct {
	EncryptionArgs
	Ciphertext []byte
}

type EncryptResult struct {
	Ciphertext []byte
}

type DecryptResult struct {
	Plaintext []byte
}

// Encrypt data using a symmetric key derived from the protocol, key ID, and counterparty.
// The encrypted data can only be decrypted by the intended recipient.
func (w *Wallet) Encrypt(args EncryptArgs) (*EncryptResult, error) {
	if args.Counterparty.Type == CounterpartyUninitialized {
		args.Counterparty = WalletCounterparty{
			Type: CounterpartyTypeSelf,
		}
	}

	key, err := w.keyDeriver.DeriveSymmetricKey(args.ProtocolID, args.KeyID, args.Counterparty)
	if err != nil {
		return nil, fmt.Errorf("failed to derive symmetric key: %w", err)
	}

	ciphertext, err := key.Encrypt(args.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}
	return &EncryptResult{Ciphertext: ciphertext}, nil
}

// Decrypt data that was encrypted using the Encrypt method.
// The protocol, key ID, and counterparty must match those used during encryption.
func (w *Wallet) Decrypt(args DecryptArgs) (*DecryptResult, error) {
	if args.Counterparty.Type == CounterpartyUninitialized {
		args.Counterparty = WalletCounterparty{
			Type: CounterpartyTypeSelf,
		}
	}

	key, err := w.keyDeriver.DeriveSymmetricKey(args.ProtocolID, args.KeyID, args.Counterparty)
	if err != nil {
		return nil, fmt.Errorf("failed to derive symmetric key: %w", err)
	}

	plaintext, err := key.Decrypt(args.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}
	return &DecryptResult{Plaintext: plaintext}, nil
}

type GetPublicKeyArgs struct {
	EncryptionArgs
	IdentityKey bool
	ForSelf     bool
}

type GetPublicKeyResult struct {
	PublicKey *ec.PublicKey `json:"publicKey"`
}

func (w *Wallet) GetPublicKey(args GetPublicKeyArgs, originator string) (*GetPublicKeyResult, error) {
	if args.IdentityKey {
		return &GetPublicKeyResult{
			PublicKey: w.keyDeriver.rootKey.PubKey(),
		}, nil
	}

	if args.ProtocolID.Protocol == "" || args.KeyID == "" {
		return nil, errors.New("protocolID and keyID are required if identityKey is false or undefined")
	}

	// Handle default counterparty (self)
	counterparty := args.Counterparty
	if counterparty.Type == CounterpartyUninitialized {
		counterparty = WalletCounterparty{
			Type: CounterpartyTypeSelf,
		}
	}

	pubKey, err := w.keyDeriver.DerivePublicKey(
		args.ProtocolID,
		args.KeyID,
		counterparty,
		args.ForSelf,
	)
	if err != nil {
		return nil, err
	}

	return &GetPublicKeyResult{
		PublicKey: pubKey,
	}, nil
}

type CreateSignatureArgs struct {
	EncryptionArgs
	Data               []byte
	DashToDirectlySign []byte
}

type CreateSignatureResult struct {
	Signature ec.Signature
}

type SignOutputs transaction.Flag

var (
	SignOutputsAll    SignOutputs = SignOutputs(sighash.All)
	SignOutputsNone   SignOutputs = SignOutputs(sighash.None)
	SignOutputsSingle SignOutputs = SignOutputs(sighash.Single)
)

// CreateSignature generates a cryptographic signature over the provided data.
// The signature is created using a private key derived from the protocol and key ID.
func (w *Wallet) CreateSignature(args CreateSignatureArgs, originator string) (*CreateSignatureResult, error) {
	if len(args.Data) == 0 && len(args.DashToDirectlySign) == 0 {
		return nil, fmt.Errorf("args.data or args.hashToDirectlySign must be valid")
	}

	// Get hash to sign
	var hash []byte
	if len(args.DashToDirectlySign) > 0 {
		hash = args.DashToDirectlySign
	} else {
		sum := sha256.Sum256(args.Data)
		hash = sum[:]
	}

	// Handle default counterparty (anyone for signing)
	counterparty := args.Counterparty
	if counterparty.Type == CounterpartyUninitialized {
		counterparty = WalletCounterparty{
			Type: CounterpartyTypeAnyone,
		}
	}

	// Derive private key
	privKey, err := w.keyDeriver.DerivePrivateKey(
		args.ProtocolID,
		args.KeyID,
		counterparty,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to derive private key: %w", err)
	}

	// Create signature
	signature, err := privKey.Sign(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature: %w", err)
	}

	return &CreateSignatureResult{
		Signature: *signature,
	}, nil
}

type VerifySignatureArgs struct {
	EncryptionArgs
	Data                 []byte
	HashToDirectlyVerify []byte
	Signature            ec.Signature
	ForSelf              bool
}

type CreateHmacArgs struct {
	EncryptionArgs
	Data []byte
}

type CreateHmacResult struct {
	Hmac []byte
}

type VerifyHmacArgs struct {
	EncryptionArgs
	Data []byte
	Hmac []byte
}

type VerifyHmacResult struct {
	Valid bool
}

type VerifySignatureResult struct {
	Valid bool
}

// VerifySignature checks the validity of a cryptographic signature.
// It verifies that the signature was created using the expected protocol and key ID.
func (w *Wallet) VerifySignature(args VerifySignatureArgs) (*VerifySignatureResult, error) {
	if len(args.Data) == 0 && len(args.HashToDirectlyVerify) == 0 {
		return nil, fmt.Errorf("args.data or args.hashToDirectlyVerify must be valid")
	}

	// Get hash to verify
	var hash []byte
	if len(args.HashToDirectlyVerify) > 0 {
		hash = args.HashToDirectlyVerify
	} else {
		sum := sha256.Sum256(args.Data)
		hash = sum[:]
	}

	// Handle default counterparty (self for verification)
	counterparty := args.Counterparty
	if counterparty.Type == CounterpartyUninitialized {
		counterparty = WalletCounterparty{
			Type: CounterpartyTypeSelf,
		}
	}

	// Derive public key
	pubKey, err := w.keyDeriver.DerivePublicKey(
		args.ProtocolID,
		args.KeyID,
		counterparty,
		args.ForSelf,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	// Verify signature
	valid := args.Signature.Verify(hash, pubKey)
	if !valid {
		return nil, fmt.Errorf("signature is not valid")
	}

	return &VerifySignatureResult{
		Valid: valid,
	}, nil
}

func AnyoneKey() (*ec.PrivateKey, *ec.PublicKey) {
	return ec.PrivateKeyFromBytes([]byte{1})
}

// CreateHmac generates an HMAC (Hash-based Message Authentication Code) for the provided data
// using a symmetric key derived from the protocol, key ID, and counterparty.
func (w *Wallet) CreateHmac(args CreateHmacArgs) (*CreateHmacResult, error) {
	if args.Counterparty.Type == CounterpartyUninitialized {
		args.Counterparty = WalletCounterparty{
			Type: CounterpartyTypeSelf,
		}
	}

	key, err := w.keyDeriver.DeriveSymmetricKey(args.ProtocolID, args.KeyID, args.Counterparty)
	if err != nil {
		return nil, fmt.Errorf("failed to derive symmetric key: %w", err)
	}

	mac := hmac.New(sha256.New, key.ToBytes())
	mac.Write(args.Data)
	hmac := mac.Sum(nil)

	return &CreateHmacResult{Hmac: hmac}, nil
}

// VerifyHmac verifies that the provided HMAC matches the expected value for the given data.
// The verification uses the same protocol, key ID, and counterparty that were used to create the HMAC.
func (w *Wallet) VerifyHmac(args VerifyHmacArgs) (*VerifyHmacResult, error) {
	if args.Counterparty.Type == CounterpartyUninitialized {
		args.Counterparty = WalletCounterparty{
			Type: CounterpartyTypeSelf,
		}
	}

	key, err := w.keyDeriver.DeriveSymmetricKey(args.ProtocolID, args.KeyID, args.Counterparty)
	if err != nil {
		return nil, fmt.Errorf("failed to derive symmetric key: %w", err)
	}

	mac := hmac.New(sha256.New, key.ToBytes())
	mac.Write(args.Data)
	expectedHmac := mac.Sum(nil)

	if !hmac.Equal(expectedHmac, args.Hmac) {
		return nil, errors.New("HMAC is not valid")
	}

	return &VerifyHmacResult{Valid: true}, nil
}
