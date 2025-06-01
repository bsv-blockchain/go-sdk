// Package wallet provides a comprehensive interface for wallet operations in the BSV blockchain.
// It defines the core Interface with 29 methods covering transaction management, certificate
// operations, cryptographic functions, and blockchain queries. The package includes ProtoWallet
// for basic operations, key derivation utilities, and a complete serializer framework for the
// wallet wire protocol. This design maintains compatibility with the TypeScript SDK while
// following Go idioms and best practices.
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
	case "":
		c.Type = CounterpartyUninitialized
	default:
		// Attempt to parse as a public key string
		pubKey, err := ec.PublicKeyFromString(s)
		if err != nil {
			return fmt.Errorf("error unmarshaling counterparty: %w", err)
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
	Plaintext JsonByteNoBase64 `json:"plaintext"`
}

type DecryptArgs struct {
	EncryptionArgs
	Ciphertext JsonByteNoBase64 `json:"ciphertext"`
}

type EncryptResult struct {
	Ciphertext JsonByteNoBase64 `json:"ciphertext"`
}

type DecryptResult struct {
	Plaintext JsonByteNoBase64 `json:"plaintext"`
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
	Data               JsonByteNoBase64 `json:"data,omitempty"`
	HashToDirectlySign JsonByteNoBase64 `json:"hashToDirectlySign,omitempty"`
}

type CreateSignatureResult struct {
	Signature ec.Signature `json:"-"` // Ignore original field for JSON
}

// MarshalJSON implements the json.Marshaler interface for CreateSignatureResult.
func (c CreateSignatureResult) MarshalJSON() ([]byte, error) {
	// Use an alias struct with JsonSignature for marshaling
	type Alias CreateSignatureResult
	return json.Marshal(&struct {
		*Alias
		Signature JsonSignature `json:"signature"` // Override Signature field
	}{
		Alias:     (*Alias)(&c),
		Signature: JsonSignature{Signature: c.Signature},
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface for CreateSignatureResult.
func (c *CreateSignatureResult) UnmarshalJSON(data []byte) error {
	// Use an alias struct with JsonSignature for unmarshaling
	type Alias CreateSignatureResult
	aux := &struct {
		*Alias
		Signature JsonSignature `json:"signature"` // Override Signature field
	}{
		Alias: (*Alias)(c),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Assign the unmarshaled signature back
	c.Signature = aux.Signature.Signature
	return nil
}

type SignOutputs sighash.Flag

var (
	SignOutputsAll    SignOutputs = SignOutputs(sighash.All)
	SignOutputsNone   SignOutputs = SignOutputs(sighash.None)
	SignOutputsSingle SignOutputs = SignOutputs(sighash.Single)
)

type JsonSignature struct {
	ec.Signature
}

func (s *JsonSignature) MarshalJSON() ([]byte, error) {
	sig := s.Serialize()
	sigInts := make([]uint16, len(sig))
	for i, b := range sig {
		sigInts[i] = uint16(b)
	}
	return json.Marshal(sigInts)
}

func (s *JsonSignature) UnmarshalJSON(data []byte) error {
	var sigBytes []byte
	// Unmarshal directly from JSON array of numbers into byte slice
	if err := json.Unmarshal(data, &sigBytes); err != nil {
		return fmt.Errorf("could not unmarshal signature byte array: %w", err)
	}
	// Parse the raw bytes as DER.
	sig, err := ec.FromDER(sigBytes)
	if err != nil {
		return fmt.Errorf("could not parse signature from DER: %w", err)
	}
	s.Signature = *sig
	return nil
}

type VerifySignatureArgs struct {
	EncryptionArgs
	Data                 JsonByteNoBase64 `json:"data,omitempty"`
	HashToDirectlyVerify JsonByteNoBase64 `json:"hashToDirectlyVerify,omitempty"`
	Signature            ec.Signature     `json:"-"` // Ignore original field for JSON
	ForSelf              bool             `json:"forSelf,omitempty"`
}

// MarshalJSON implements the json.Marshaler interface for VerifySignatureArgs.
func (v VerifySignatureArgs) MarshalJSON() ([]byte, error) {
	// Use an alias struct with JsonSignature for marshaling
	type Alias VerifySignatureArgs
	return json.Marshal(&struct {
		*Alias
		Signature JsonSignature `json:"signature"` // Override Signature field
	}{
		Alias:     (*Alias)(&v),
		Signature: JsonSignature{Signature: v.Signature},
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface for VerifySignatureArgs.
func (v *VerifySignatureArgs) UnmarshalJSON(data []byte) error {
	// Use an alias struct with JsonSignature for unmarshaling
	type Alias VerifySignatureArgs
	aux := &struct {
		*Alias
		Signature JsonSignature `json:"signature"` // Override Signature field
	}{
		Alias: (*Alias)(v),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Assign the unmarshaled signature back
	v.Signature = aux.Signature.Signature
	return nil
}

type CreateHmacArgs struct {
	EncryptionArgs
	Data JsonByteNoBase64 `json:"data"`
}

type CreateHmacResult struct {
	Hmac JsonByteNoBase64 `json:"hmac"`
}

type VerifyHmacArgs struct {
	EncryptionArgs
	Data JsonByteNoBase64 `json:"data"`
	Hmac JsonByteNoBase64 `json:"hmac"`
}

type VerifyHmacResult struct {
	Valid bool `json:"valid"`
}

type VerifySignatureResult struct {
	Valid bool `json:"valid"`
}

func AnyoneKey() (*ec.PrivateKey, *ec.PublicKey) {
	return ec.PrivateKeyFromBytes([]byte{1})
}
