package wallet

import (
	"encoding/json"
	"fmt"

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

func (p *Protocol) MarshalJSON() ([]byte, error) {
	return json.Marshal([]interface{}{p.SecurityLevel, p.Protocol})
}

func (p *Protocol) UnmarshalJSON(data []byte) error {
	var temp []interface{}
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	if len(temp) != 2 {
		return fmt.Errorf("expected array of length 2, but got %d", len(temp))
	}

	securityLevel, ok := temp[0].(float64)
	if !ok {
		return fmt.Errorf("expected SecurityLevel to be a number, but got %T", temp[0])
	}
	p.SecurityLevel = SecurityLevel(securityLevel)

	protocol, ok := temp[1].(string)
	if !ok {
		return fmt.Errorf("expected Protocol to be a string, but got %T", temp[1])
	}
	p.Protocol = protocol

	return nil
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

func (c *Counterparty) MarshalJSON() ([]byte, error) {
	switch c.Type {
	case CounterpartyTypeAnyone:
		return json.Marshal("anyone")
	case CounterpartyTypeSelf:
		return json.Marshal("self")
	case CounterpartyTypeOther:
		if c.Counterparty == nil {
			return json.Marshal(nil) // Or handle this as an error if it should never happen
		}
		return json.Marshal(c.Counterparty.ToDERHex())
	default:
		return json.Marshal(nil) // Or handle this as an error if it should never happen
	}
}

func (c *Counterparty) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("could not unmarshal Counterparty from JSON: %s", string(data))
	}
	switch s {
	case "anyone":
		c.Type = CounterpartyTypeAnyone
	case "self":
		c.Type = CounterpartyTypeSelf
	default:
		// Attempt to parse as a public key string
		pubKey, err := ec.PublicKeyFromString(s)
		if err != nil {
			return err
		}
		c.Type = CounterpartyTypeOther
		c.Counterparty = pubKey
	}
	return nil
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
	ProtocolID       Protocol     `json:"protocolID,omitempty"`
	KeyID            string       `json:"keyID,omitempty"`
	Counterparty     Counterparty `json:"counterparty,omitempty"`
	Privileged       bool         `json:"privileged,omitempty"`
	PrivilegedReason string       `json:"privilegedReason,omitempty"`
	SeekPermission   bool         `json:"seekPermission,omitempty"`
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
	IdentityKey bool `json:"identityKey"`
	ForSelf     bool `json:"forSelf,omitempty"`
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
