package wallet

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

type keyDeriverInterface interface {
	DerivePrivateKey(protocol WalletProtocol, keyID string, counterparty WalletCounterparty) (*ec.PrivateKey, error)
	DerivePublicKey(protocol WalletProtocol, keyID string, counterparty WalletCounterparty, forSelf bool) (*ec.PublicKey, error)
	DeriveSymmetricKey(protocol WalletProtocol, keyID string, counterparty WalletCounterparty) (*ec.SymmetricKey, error)
}

// KeyDeriver is responsible for deriving various types of keys using a root private key.
// It supports deriving public and private keys, symmetric keys, and revealing key linkages.
type KeyDeriver struct {
	rootKey *ec.PrivateKey
}

// NewKeyDeriver creates a new KeyDeriver instance with a root private key.
// The root key can be either a specific private key or the special 'anyone' key.
func NewKeyDeriver(privateKey *ec.PrivateKey) *KeyDeriver {
	if privateKey == nil {
		privateKey, _ = AnyoneKey()
	}
	return &KeyDeriver{
		rootKey: privateKey,
	}
}

// DeriveSymmetricKey creates a symmetric key based on protocol ID, key ID, and counterparty.
// Note: Symmetric keys should not be derivable by everyone due to security risks.
func (kd *KeyDeriver) DeriveSymmetricKey(protocol WalletProtocol, keyID string, counterparty WalletCounterparty) (*ec.SymmetricKey, error) {
	// If counterparty is 'anyone', use a fixed public key
	if counterparty.Type == CounterpartyTypeAnyone {
		_, anyonePubKey := AnyoneKey()
		counterparty = WalletCounterparty{
			Type:         CounterpartyTypeOther,
			Counterparty: anyonePubKey,
		}
	}

	// Derive both public and private keys
	derivedPublicKey, err := kd.DerivePublicKey(protocol, keyID, counterparty, false)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	derivedPrivateKey, err := kd.DerivePrivateKey(protocol, keyID, counterparty)
	if err != nil {
		return nil, fmt.Errorf("failed to derive private key: %w", err)
	}

	// Create shared secret
	sharedSecret, err := derivedPrivateKey.DeriveSharedSecret(derivedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create shared secret: %w", err)
	}
	if sharedSecret == nil {
		return nil, fmt.Errorf("failed to derive shared secret")
	}

	// Return the x coordinate of the shared secret point
	return ec.NewSymmetricKey(sharedSecret.X.Bytes()), nil
}

// DerivePublicKey creates a public key based on protocol ID, key ID, and counterparty.
func (kd *KeyDeriver) DerivePublicKey(protocol WalletProtocol, keyID string, counterparty WalletCounterparty, forSelf bool) (*ec.PublicKey, error) {
	counterpartyKey, err := kd.normalizeCounterparty(counterparty)
	if err != nil {
		return nil, err
	}
	invoiceNumber, err := kd.computeInvoiceNumber(protocol, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to compute invoice number: %w", err)
	}

	if forSelf {
		privKey, err := kd.rootKey.DeriveChild(counterpartyKey, invoiceNumber)
		if err != nil {
			return nil, fmt.Errorf("failed to derive child private key: %w", err)
		}
		return privKey.PubKey(), nil
	}

	pubKey, err := counterpartyKey.DeriveChild(kd.rootKey, invoiceNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to derive child public key: %w", err)
	}
	return pubKey, nil
}

// DerivePrivateKey creates a private key based on protocol ID, key ID, and counterparty.
// The derived key can be used for signing or other cryptographic operations.
func (kd *KeyDeriver) DerivePrivateKey(protocol WalletProtocol, keyID string, counterparty WalletCounterparty) (*ec.PrivateKey, error) {
	counterpartyKey, err := kd.normalizeCounterparty(counterparty)
	if err != nil {
		return nil, err
	}
	invoiceNumber, err := kd.computeInvoiceNumber(protocol, keyID)
	if err != nil {
		return nil, err
	}

	k, err := kd.rootKey.DeriveChild(counterpartyKey, invoiceNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to derive child key: %w", err)
	}
	return k, nil
}

// normalizeCounterparty converts the counterparty parameter into a standard public key format.
// It handles special cases like 'self' and 'anyone' by converting them to their corresponding public keys.
func (kd *KeyDeriver) normalizeCounterparty(counterparty WalletCounterparty) (*ec.PublicKey, error) {
	switch counterparty.Type {
	case CounterpartyTypeSelf:
		return kd.rootKey.PubKey(), nil
	case CounterpartyTypeOther:
		if counterparty.Counterparty == nil {
			return nil, errors.New("counterparty public key required for other")
		}
		return counterparty.Counterparty, nil
	case CounterpartyTypeAnyone:
		_, pub := AnyoneKey()
		return pub, nil
	default:
		return nil, errors.New("invalid counterparty, must be self, other, or anyone")
	}
}

// RevealCounterpartySecret reveals the shared secret between the root key and the counterparty.
// Note: This should not be used for 'self'.
func (kd *KeyDeriver) RevealCounterpartySecret(counterparty WalletCounterparty) (*ec.PublicKey, error) {
	if counterparty.Type == CounterpartyTypeSelf {
		return nil, errors.New("counterparty secrets cannot be revealed for counterparty=self")
	}

	counterpartyKey, err := kd.normalizeCounterparty(counterparty)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize counterparty: %w", err)
	}

	// Double-check to ensure not revealing the secret for 'self'
	self := kd.rootKey.PubKey()
	keyDerivedBySelf, err := kd.rootKey.DeriveChild(self, "test")
	if err != nil {
		return nil, fmt.Errorf("failed to derive self key: %w", err)
	}

	keyDerivedByCounterparty, err := kd.rootKey.DeriveChild(counterpartyKey, "test")
	if err != nil {
		return nil, fmt.Errorf("failed to derive counterparty key: %w", err)
	}

	if bytes.Equal(keyDerivedBySelf.Serialize(), keyDerivedByCounterparty.Serialize()) {
		return nil, errors.New("counterparty secrets cannot be revealed if counterparty key is self")
	}

	sharedSecret, err := kd.rootKey.DeriveSharedSecret(counterpartyKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}

	return sharedSecret, nil
}

var regexOnlyLettersNumbersSpaces = regexp.MustCompile(`^[a-z0-9 ]+$`)

// computeInvoiceNumber generates a unique identifier string based on the protocol and key ID.
// This string is used as part of the key derivation process to ensure unique keys for different contexts.
func (kd *KeyDeriver) computeInvoiceNumber(protocol WalletProtocol, keyID string) (string, error) {
	// Validate protocol security level
	if protocol.SecurityLevel < 0 || protocol.SecurityLevel > 2 {
		return "", fmt.Errorf("protocol security level must be 0, 1, or 2")
	}

	// Validate key ID
	if len(keyID) > 800 {
		return "", fmt.Errorf("key IDs must be 800 characters or less")
	}
	if len(keyID) < 1 {
		return "", fmt.Errorf("key IDs must be 1 character or more")
	}

	// Validate protocol name
	protocolName := strings.ToLower(strings.TrimSpace(protocol.Protocol))
	if len(protocolName) > 400 {
		// Special handling for specific linkage revelation
		if strings.HasPrefix(protocolName, "specific linkage revelation ") {
			if len(protocolName) > 430 {
				return "", fmt.Errorf("specific linkage revelation protocol names must be 430 characters or less")
			}
		} else {
			return "", fmt.Errorf("protocol names must be 400 characters or less")
		}
	}
	if len(protocolName) < 5 {
		return "", fmt.Errorf("protocol names must be 5 characters or more")
	}
	if strings.Contains(protocolName, "  ") {
		return "", fmt.Errorf("protocol names cannot contain multiple consecutive spaces (\"  \")")
	}
	if !regexOnlyLettersNumbersSpaces.MatchString(protocolName) {
		return "", fmt.Errorf("protocol names can only contain letters, numbers and spaces")
	}
	if strings.HasSuffix(protocolName, " protocol") {
		return "", fmt.Errorf("no need to end your protocol name with \" protocol\"")
	}

	return fmt.Sprintf("%d-%s-%s", protocol.SecurityLevel, protocolName, keyID), nil
}
