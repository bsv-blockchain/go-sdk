package wallet

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// WIF represents a string holding private key in WIF format.
// To pass a string as WIF simply wrap it with WIF type.
type WIF string

// PrivateKey returns the private key from the WIF string.
func (w WIF) PrivateKey() (*ec.PrivateKey, error) {
	return ec.PrivateKeyFromWif(string(w)) //nolint:wrapcheck
}

// PrivateKeySource represents a source of wallet owner private key.
// Can be used with different types of sources:
//   - string: a private key in HEX format
//   - WIF: a private key in WIF format string
//   - *ec.PrivateKey: a private key object
type PrivateKeySource interface {
	string | WIF | *ec.PrivateKey
}

// WalletKeySource represents a source of wallet owner private key.
// Can be used with different types of sources:
//   - string: a private key in HEX format
//   - WIF: a private key in WIF format string
//   - *ec.PrivateKey: a private key object
//   - *sdk.KeyDeriver: a key deriver that can be used to derive the private key
type WalletKeySource interface {
	PrivateKeySource | *KeyDeriver
}

// IdentityKeySource represents a source of identity key.
// Can be used with different types of sources:
//   - string: a public key in DER HEX format
//   - *sdk.KeyDeriver: a key deriver that can be used to derive the public key
//   - *ec.PublicKey: a public key object
type IdentityKeySource interface {
	string | WIF | *KeyDeriver | *ec.PublicKey
}

// ToPrivateKey converts a PrivateKeySource into an *ec.PrivateKey or returns an error if the conversion fails.
// Can be used with different types of sources:
//   - string: a private key in HEX format
//   - WIF: a private key in WIF format string
//   - *ec.PrivateKey: a private key object
func ToPrivateKey[KeySource PrivateKeySource](keySource KeySource) (*ec.PrivateKey, error) {
	switch k := any(keySource).(type) {
	case string:
		priv, err := ec.PrivateKeyFromHex(k)
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
//   - string: a private key in HEX format
//   - WIF: a private key in WIF format string
//   - *sdk.KeyDeriver: a key deriver that can be used to derive the private key
//   - *ec.PrivateKey: a private key object
func ToKeyDeriver[KeySource WalletKeySource](keySource KeySource) (*KeyDeriver, error) {
	switch k := any(keySource).(type) {
	case string:
		priv, err := ec.PrivateKeyFromHex(k)
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

// ToIdentityKey converts an IdentityKeySource into an *ec.PublicKey, handling various input types.
// Can be used with different types of sources:
//   - string: a public key in DER HEX format
//   - *sdk.KeyDeriver: a key deriver
//   - *ec.PublicKey: a public key object
//   - WIF: a private key in WIF format string
func ToIdentityKey[KeySource IdentityKeySource](keySource KeySource) (*ec.PublicKey, error) {
	switch k := any(keySource).(type) {
	case string:
		pubKey, err := ec.PublicKeyFromString(k)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key from string: %w", err)
		}
		return pubKey, nil
	case WIF:
		privKey, err := k.PrivateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key from string containing WIF: %w", err)
		}
		return privKey.PubKey(), nil
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
	default:
		return nil, fmt.Errorf("unexpected key source type: %T, ensure that all subtypes of key source are handled", k)
	}
}
