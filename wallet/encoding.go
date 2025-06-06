package wallet

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// BytesList is a custom type for JSON serialization of byte arrays that don't use base64 encoding.
type BytesList []byte

func (s BytesList) MarshalJSON() ([]byte, error) {
	// Marshal as a plain number array, not base64
	arr := make([]uint16, len(s))
	for i, b := range s {
		arr[i] = uint16(b)
	}
	return json.Marshal(arr)
}

func (s *BytesList) UnmarshalJSON(data []byte) error {
	var temp []uint8
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	*s = temp
	return nil
}

// BytesHex is a helper type for marshaling byte slices as hex strings.
type BytesHex []byte

// MarshalJSON implements the json.Marshaler interface.
func (s BytesHex) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(s))
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (s *BytesHex) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	bytes, err := hex.DecodeString(str)
	if err != nil {
		return err
	}
	*s = bytes
	return nil
}

type Bytes32Base64 [32]byte

func (b Bytes32Base64) MarshalJSON() ([]byte, error) {
	s := base64.StdEncoding.EncodeToString(b[:])
	return json.Marshal(s)
}

func (b *Bytes32Base64) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	if len(decoded) != 32 {
		return fmt.Errorf("expected 32 bytes, got %d", len(decoded))
	}
	copy(b[:], decoded)
	return nil
}

type Bytes33Hex [33]byte

func (b Bytes33Hex) MarshalJSON() ([]byte, error) {
	s := hex.EncodeToString(b[:])
	return json.Marshal(s)
}

func (b *Bytes33Hex) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(decoded) != 33 {
		return fmt.Errorf("expected 33 bytes, got %d", len(decoded))
	}
	copy(b[:], decoded)
	return nil
}

// StringBase64 represents a string that should be base64 encoded in certain contexts.
type StringBase64 string

func (s StringBase64) ToArray() ([32]byte, error) {
	b, err := base64.StdEncoding.DecodeString(string(s))
	if err != nil {
		return [32]byte{}, fmt.Errorf("error decoding base64 string: %w", err)
	}

	var arr [32]byte
	if len(b) > 32 {
		return arr, fmt.Errorf("string too long: %d", len(b))
	}
	if len(b) == 0 {
		return arr, nil
	}
	copy(arr[:], b)
	return arr, nil
}

func StringBase64FromArray(arr [32]byte) StringBase64 {
	return StringBase64(base64.StdEncoding.EncodeToString(arr[:]))
}

// Signature is a wrapper around ec.Signature that provides custom JSON marshaling.
// It serializes signatures as arrays of byte values rather than base64 strings.
type Signature ec.Signature

// MarshalJSON implements the json.Marshaler interface for Signature.
// It serializes the signature as an array of byte values.
func (s Signature) MarshalJSON() ([]byte, error) {
	if (*ec.Signature)(&s).R == nil || (*ec.Signature)(&s).S == nil {
		return json.Marshal(nil)
	}
	sig := (*ec.Signature)(&s).Serialize()
	return json.Marshal(BytesList(sig))
}

// UnmarshalJSON implements the json.Unmarshaler interface for Signature.
// It deserializes an array of byte values back into a signature.
func (s *Signature) UnmarshalJSON(data []byte) error {
	var sigBytes BytesList
	if err := json.Unmarshal(data, &sigBytes); err != nil {
		return fmt.Errorf("could not unmarshal signature byte array: %w", err)
	}
	sig, err := ec.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("could not parse signature from byte array: %w", err)
	}
	*s = Signature(*sig)
	return nil
}
