package wallet

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// WIF represents a string holding private key in WIF format.
// To pass a string as WIF simply wrap it with WIF type, like WIF("L1...").
type WIF string

// PrivateKey returns the private key from the WIF string.
func (w WIF) PrivateKey() (*ec.PrivateKey, error) {
	return ec.PrivateKeyFromWif(string(w)) //nolint:wrapcheck
}

// PrivHex represents a string holding private key in HEX format.
// To pass a string as PrivHex simply wrap it with PrivHex type, like PrivHex("ab...").
type PrivHex string

// PrivateKey returns the private key from the PrivHex string.
func (k PrivHex) PrivateKey() (*ec.PrivateKey, error) {
	return ec.PrivateKeyFromHex(string(k)) //nolint:wrapcheck
}

// PrivateKeySource represents a source of wallet owner private key.
// Can be used with different types of sources:
//   - PrivHex: a private key in HEX format - to pass it, you simply wrap string with PrivHex type, like PrivHex("ab...")
//   - WIF: a private key in WIF format string - to pass it, you simply wrap string with WIF type, like WIF("L1...")
//   - *ec.PrivateKey: a private key object
type PrivateKeySource interface {
	PrivHex | WIF | *ec.PrivateKey
}

// WalletKeySource represents a source of wallet owner private key.
// Can be used with different types of sources:
//   - PrivHex: a private key in HEX format - to pass it, you simply wrap string with PrivHex type, like PrivHex("ab...")
//   - WIF: a private key in WIF format string - to pass it, you simply wrap string with WIF type, like WIF("L1...")
//   - *ec.PrivateKey: a private key object
//   - *sdk.KeyDeriver: a key deriver that can be used to derive the private key
type WalletKeySource interface {
	PrivateKeySource | *KeyDeriver
}

// ToPrivateKey converts a PrivateKeySource into an *ec.PrivateKey or returns an error if the conversion fails.
// Can be used with different types of sources:
//   - PrivHex: a private key in HEX format - to pass it, you simply wrap string with PrivHex type, like PrivHex("ab...")
//   - WIF: a private key in WIF format string - to pass it, you simply wrap string with WIF type, like WIF("L1...")
//   - *ec.PrivateKey: a private key object
//
// Examples:
//
//  1. From hex string
//     ```go
//     privKey, err := ToPrivateKey(PrivHex("ab..."))
//     ```
//
//  2. From WIF string
//     ```go
//     privKey, err := ToPrivateKey(WIF("L1..."))
//     ```
//
//  3. From private key object
//     ```go
//     var pk *ec.PrivateKey = ...
//     privKey, err := ToPrivateKey(pk)
//     ```
func ToPrivateKey[KeySource PrivateKeySource](keySource KeySource) (*ec.PrivateKey, error) {
	switch k := any(keySource).(type) {
	case PrivHex:
		priv, err := k.PrivateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key from string hex %q: %w", k, err)
		}
		return priv, nil
	case WIF:
		priv, err := k.PrivateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key from string containing WIF %q: %w", k, err)
		}
		return priv, nil
	case *ec.PrivateKey:
		if k == nil {
			return nil, fmt.Errorf("private key (%T) cannot be nil", k)
		}
		return k, nil
	default:
		// should never happen because of compiler
		panic(fmt.Errorf("unexpected key source type: %T, ensure that all subtypes of key source are handled", k))
	}
}

// ToKeyDeriver converts a PrivateKeySource or a KeyDeriver pointer into a *KeyDeriver, handling various input types.
// Can be used with different types of sources:
//   - PrivHex: a private key in HEX format - to pass it, you simply wrap string with PrivHex type, like PrivHex("ab...")
//   - WIF: a private key in WIF format string - to pass it, you simply wrap string with WIF type, like WIF("L1...")
//   - *sdk.KeyDeriver: a key deriver that can be used to derive the private key
//   - *ec.PrivateKey: a private key object
//
// Examples:
//
//  1. From hex string
//     ```go
//     keyDeriver, err := ToKeyDeriver(PrivHex("ab..."))
//     ```
//
//  2. From WIF string
//     ```go
//     keyDeriver, err := ToKeyDeriver(WIF("L1..."))
//     ```
//
//  3. From key deriver
//     ```go
//     var keyDeriver *sdk.KeyDeriver = ...
//     keyDeriver, err := ToKeyDeriver(keyDeriver)
//     ```
//
//  4. From private key object
//     ```go
//     var pk *ec.PrivateKey = ...
//     keyDeriver, err := ToKeyDeriver(pk)
//     ```
func ToKeyDeriver[KeySource WalletKeySource](keySource KeySource) (*KeyDeriver, error) {
	switch k := any(keySource).(type) {
	case PrivHex:
		priv, err := k.PrivateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key from string hex %q: %w", k, err)
		}
		return NewKeyDeriver(priv), nil
	case WIF:
		priv, err := k.PrivateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key from string containing WIF %q: %w", k, err)
		}
		return NewKeyDeriver(priv), nil
	case *ec.PrivateKey:
		if k == nil {
			return nil, fmt.Errorf("private key (%T) cannot be nil", k)
		}
		return NewKeyDeriver(k), nil
	case *KeyDeriver:
		if k == nil {
			return nil, fmt.Errorf("key deriver (%T) cannot be nil", k)
		}
		return k, nil
	default:
		return nil, fmt.Errorf("unexpected key source type: %T, ensure that all subtypes of key source are handled", k)
	}
}

// PubHex represents a string holding a public key in DER HEX format.
// To pass a string as PubHex simply wrap it with PubHex type, like PubHex("ab...").
type PubHex string

// PublicKey returns the public key from the PubHex string.
func (k PubHex) PublicKey() (*ec.PublicKey, error) {
	return ec.PublicKeyFromString(string(k)) //nolint:wrapcheck
}

// IdentityKeyPublicSource represents a source of identity key.
// Can be used with different types of sources:
//   - PubHex: a public key in HEX format - to pass it, you simply wrap string with PubHex type, like PubHex("ab...")
//   - *sdk.KeyDeriver: a key deriver that can be used to derive the public key
//   - *ec.PublicKey: a public key object
type IdentityKeyPublicSource interface {
	PubHex | *KeyDeriver | *ec.PublicKey
}

// IdentityKeySource represents a source of identity key.
// Can be used with different types of sources:
//   - PubHex: a public key in HEX format - to pass it, you simply wrap string with PubHex type, like PubHex("ab...")
//   - *sdk.KeyDeriver: a key deriver that can be used to derive the public key
//   - *ec.PublicKey: a public key object
//   - PrivHex: a private key in HEX format - to pass it, you simply wrap string with PrivHex type, like PrivHex("ab...")
//   - WIF: a private key in WIF format string - to pass it, you simply wrap string with WIF type, like WIF("L1...")
//   - *ec.PrivateKey: a private key object
type IdentityKeySource interface {
	IdentityKeyPublicSource | PrivHex | WIF | *ec.PrivateKey
}

// ToIdentityKey converts an IdentityKeySource into an *ec.PublicKey, handling various input types.
// Can be used with different types of sources:
//   - PubHex: a public key in HEX format - to pass it, you simply wrap string with PubHex type, like PubHex("ab...")
//   - *sdk.KeyDeriver: a key deriver that can be used to derive the public key
//   - *ec.PublicKey: a public key object
//   - PrivHex: a private key in HEX format - to pass it, you simply wrap string with PrivHex type, like PrivHex("ab...")
//   - WIF: a private key in WIF format string - to pass it, you simply wrap string with WIF type, like WIF("L1...")
//   - *ec.PrivateKey: a private key object
//
// Examples:
//
//  1. From hex string
//     ```go
//     pubKey, err := ToIdentityKey(PubHex("ab..."))
//     ```
//
//  2. From key deriver
//     ```go
//     var keyDeriver *sdk.KeyDeriver = ...
//     pubKey, err := ToIdentityKey(keyDeriver)
//     ```
//
//  3. From public key object
//     ```go
//     var pubKey *ec.PublicKey = ...
//     pubKey, err := ToIdentityKey(pubKey)
//     ```
//
//  4. From private key object
//     ```go
//     var pk *ec.PrivateKey = ...
//     pubKey, err := ToIdentityKey(pk)
//     ```
//
//  5. From private key hex string
//     ```go
//     pubKey, err := ToIdentityKey(PrivHex("ab..."))
//     ```
//
//  6. From private key WIF string
//     ```go
//     pubKey, err := ToIdentityKey(WIF("L1..."))
//     ```
func ToIdentityKey[KeySource IdentityKeySource](keySource KeySource) (*ec.PublicKey, error) {
	switch k := any(keySource).(type) {
	case PubHex:
		pubKey, err := k.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key from string: %w", err)
		}
		return pubKey, nil
	case *KeyDeriver:
		if k == nil {
			return nil, fmt.Errorf("key deriver cannot be nil")
		}
		return k.IdentityKey(), nil
	case *ec.PublicKey:
		if k == nil {
			return nil, fmt.Errorf("public key cannot be nil")
		}
		return k, nil
	case PrivHex:
		pk, err := ToPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to get public key from private key hex: %w", err)
		}
		return pk.PubKey(), nil
	case WIF:
		pk, err := ToPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to get public key from WIF: %w", err)
		}
		return pk.PubKey(), nil
	case *ec.PrivateKey:
		if k == nil {
			return nil, fmt.Errorf("private key cannot be nil to produce identity key")
		}
		return k.PubKey(), nil
	default:
		return nil, fmt.Errorf("unexpected key source type: %T, ensure that all subtypes of key source are handled", k)
	}
}
