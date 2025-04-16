package wallet

import (
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// SecurityLevel defines the access control level for wallet operations.
// It determines how strictly the wallet enforces user confirmation for operations.
type SecurityLevel int

var (
	SecurityLevelSilent                  SecurityLevel = 0
	SecurityLevelEveryApp                SecurityLevel = 1
	SecurityLevelEveryAppAndCounterparty SecurityLevel = 2
)

// Protocol defines a protocol with its security level and name.
// The security level determines how strictly the wallet enforces user confirmation.
type Protocol struct {
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

// Counterparty represents the other party in a cryptographic operation.
// It can be a specific public key, or one of the special values 'self' or 'anyone'.
type Counterparty struct {
	Type         CounterpartyType
	Counterparty *ec.PublicKey
}

// Wallet provides cryptographic operations for a specific identity.
// It can encrypt/decrypt data, create/verify signatures, and manage keys.
type Wallet struct {
	ProtoWallet
}

// NewWallet creates a new wallet instance using the provided private key.
// The private key serves as the root of trust for all cryptographic operations.
func NewWallet(privateKey *ec.PrivateKey) (*Wallet, error) {
	w, err := NewProtoWallet(ProtoWalletArgs{
		Type:       ProtoWalletArgsTypePrivateKey,
		PrivateKey: privateKey,
	})
	if err != nil {
		return nil, err
	}
	return &Wallet{
		ProtoWallet: *w,
	}, nil
}

type EncryptionArgs struct {
	ProtocolID       Protocol
	KeyID            string
	Counterparty     Counterparty
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

type GetPublicKeyArgs struct {
	EncryptionArgs
	IdentityKey bool
	ForSelf     bool
}

type GetPublicKeyResult struct {
	PublicKey *ec.PublicKey `json:"publicKey"`
}

type CreateSignatureArgs struct {
	EncryptionArgs
	Data               []byte
	HashToDirectlySign []byte
}

type CreateSignatureResult struct {
	Signature ec.Signature
}

type SignOutputs sighash.Flag

var (
	SignOutputsAll    SignOutputs = SignOutputs(sighash.All)
	SignOutputsNone   SignOutputs = SignOutputs(sighash.None)
	SignOutputsSingle SignOutputs = SignOutputs(sighash.Single)
)

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

func AnyoneKey() (*ec.PrivateKey, *ec.PublicKey) {
	return ec.PrivateKeyFromBytes([]byte{1})
}
