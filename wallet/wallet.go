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

// MarshalJSON implements the json.Marshaler interface for Protocol.
// It serializes the Protocol as a JSON array containing [SecurityLevel, Protocol].
func (p *Protocol) MarshalJSON() ([]byte, error) {
	return json.Marshal([]interface{}{p.SecurityLevel, p.Protocol})
}

// UnmarshalJSON implements the json.Unmarshaler interface for Protocol.
// It deserializes a JSON array [SecurityLevel, Protocol] into the Protocol struct.
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

// CounterpartyType represents the type of counterparty in a cryptographic operation.
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

// MarshalJSON implements the json.Marshaler interface for Counterparty.
// It serializes special counterparty types as strings ("anyone", "self") and
// specific counterparties as their DER-encoded hex public key.
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

// UnmarshalJSON implements the json.Unmarshaler interface for Counterparty.
// It deserializes "anyone", "self", or a DER-encoded hex public key string
// into the appropriate Counterparty struct.
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

// EncryptionArgs contains common parameters for cryptographic operations.
// These parameters specify the protocol, key identity, counterparty, and access control settings.
type EncryptionArgs struct {
	ProtocolID       Protocol     `json:"protocolID,omitempty"`
	KeyID            string       `json:"keyID,omitempty"`
	Counterparty     Counterparty `json:"counterparty,omitempty"`
	Privileged       bool         `json:"privileged,omitempty"`
	PrivilegedReason string       `json:"privilegedReason,omitempty"`
	SeekPermission   bool         `json:"seekPermission,omitempty"`
}

// EncryptArgs contains parameters for encrypting data.
// It extends EncryptionArgs with the plaintext data to be encrypted.
type EncryptArgs struct {
	EncryptionArgs
	Plaintext JsonByteNoBase64 `json:"plaintext"`
}

// DecryptArgs contains parameters for decrypting data.
// It extends EncryptionArgs with the ciphertext data to be decrypted.
type DecryptArgs struct {
	EncryptionArgs
	Ciphertext JsonByteNoBase64 `json:"ciphertext"`
}

// EncryptResult contains the result of an encryption operation.
type EncryptResult struct {
	Ciphertext JsonByteNoBase64 `json:"ciphertext"`
}

// DecryptResult contains the result of a decryption operation.
type DecryptResult struct {
	Plaintext JsonByteNoBase64 `json:"plaintext"`
}

// GetPublicKeyArgs contains parameters for retrieving a public key.
// It extends EncryptionArgs with flags to specify identity key or derived key behavior.
type GetPublicKeyArgs struct {
	EncryptionArgs
	IdentityKey bool `json:"identityKey"`
	ForSelf     bool `json:"forSelf,omitempty"`
}

// GetPublicKeyResult contains the result of a public key retrieval operation.
type GetPublicKeyResult struct {
	PublicKey *ec.PublicKey `json:"publicKey"`
}

// CreateSignatureArgs contains parameters for creating a digital signature.
// It can sign either raw data (which will be hashed) or a pre-computed hash.
type CreateSignatureArgs struct {
	EncryptionArgs
	Data               JsonByteNoBase64 `json:"data,omitempty"`
	HashToDirectlySign JsonByteNoBase64 `json:"hashToDirectlySign,omitempty"`
}

// CreateSignatureResult contains the result of a signature creation operation.
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

// SignOutputs defines which transaction outputs should be signed using SIGHASH flags.
// It wraps the sighash.Flag type to provide specific signing behavior.
type SignOutputs sighash.Flag

var (
	SignOutputsAll    SignOutputs = SignOutputs(sighash.All)
	SignOutputsNone   SignOutputs = SignOutputs(sighash.None)
	SignOutputsSingle SignOutputs = SignOutputs(sighash.Single)
)

// JsonSignature is a wrapper around ec.Signature that provides custom JSON marshaling.
// It serializes signatures as arrays of byte values rather than base64 strings.
type JsonSignature struct {
	ec.Signature
}

// MarshalJSON implements the json.Marshaler interface for JsonSignature.
// It serializes the signature as an array of byte values.
func (s *JsonSignature) MarshalJSON() ([]byte, error) {
	sig := s.Serialize()
	sigInts := make([]uint16, len(sig))
	for i, b := range sig {
		sigInts[i] = uint16(b)
	}
	return json.Marshal(sigInts)
}

// UnmarshalJSON implements the json.Unmarshaler interface for JsonSignature.
// It deserializes an array of byte values back into a signature.
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

// VerifySignatureArgs contains parameters for verifying a digital signature.
// It can verify against either raw data (which will be hashed) or a pre-computed hash.
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

// CreateHmacArgs contains parameters for creating an HMAC.
// It extends EncryptionArgs with the data to be authenticated.
type CreateHmacArgs struct {
	EncryptionArgs
	Data JsonByteNoBase64 `json:"data"`
}

// CreateHmacResult contains the result of an HMAC creation operation.
type CreateHmacResult struct {
	Hmac JsonByteNoBase64 `json:"hmac"`
}

// VerifyHmacArgs contains parameters for verifying an HMAC.
// It extends EncryptionArgs with the data and HMAC to be verified.
type VerifyHmacArgs struct {
	EncryptionArgs
	Data JsonByteNoBase64 `json:"data"`
	Hmac JsonByteNoBase64 `json:"hmac"`
}

// VerifyHmacResult contains the result of an HMAC verification operation.
type VerifyHmacResult struct {
	Valid bool `json:"valid"`
}

// VerifySignatureResult contains the result of a signature verification operation.
type VerifySignatureResult struct {
	Valid bool `json:"valid"`
}

// AnyoneKey returns the special "anyone" private and public key pair.
// This key pair is used when no specific counterparty is specified,
// effectively making operations available to anyone.
func AnyoneKey() (*ec.PrivateKey, *ec.PublicKey) {
	return ec.PrivateKeyFromBytes([]byte{1})
}
