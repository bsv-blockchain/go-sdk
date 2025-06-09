package wallet

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/stretchr/testify/assert"
)

func TestKeyDeriver(t *testing.T) {
	rootPrivateKey, _ := ec.PrivateKeyFromBytes([]byte{42})
	rootPublicKey := rootPrivateKey.PubKey()
	counterpartyPrivateKey, _ := ec.PrivateKeyFromBytes([]byte{69})
	counterpartyPublicKey := counterpartyPrivateKey.PubKey()
	anyonePrivateKey, _ := ec.PrivateKeyFromBytes([]byte{1})
	anyonePublicKey := anyonePrivateKey.PubKey()

	protocolID := Protocol{
		SecurityLevel: SecurityLevelSilent,
		Protocol:      "testprotocol",
	}
	keyID := "12345"

	keyDeriver := NewKeyDeriver(rootPrivateKey)

	t.Run("should return public key for root key as identity key", func(t *testing.T) {
		identityKey := keyDeriver.IdentityKey()
		assert.Equalf(t, rootPublicKey, identityKey, "identity key should match root public key")
	})

	t.Run("should return DER HEX from public key for root key as identity key hex", func(t *testing.T) {
		identityKey := keyDeriver.IdentityKeyHex()
		assert.Equalf(t, rootPublicKey.ToDERHex(), identityKey, "identity key hex should match root public key hex")
	})

	t.Run("should compute the correct invoice number", func(t *testing.T) {
		invoiceNumber, err := keyDeriver.computeInvoiceNumber(protocolID, keyID)
		assert.NoError(t, err, "computing invoice number should not error")
		assert.Equal(t, "0-testprotocol-12345", invoiceNumber, "computed invoice number should match expected value")
	})

	t.Run("should normalize counterparty correctly for self", func(t *testing.T) {
		normalized, err := keyDeriver.normalizeCounterparty(Counterparty{
			Type: CounterpartyTypeSelf,
		})
		assert.NoError(t, err, "normalizing self counterparty should not error")
		assert.Equal(t, rootPublicKey.ToDERHex(), normalized.ToDERHex(), "normalized self counterparty should be root public key")
	})

	t.Run("should normalize counterparty correctly for anyone", func(t *testing.T) {
		normalized, err := keyDeriver.normalizeCounterparty(Counterparty{
			Type: CounterpartyTypeAnyone,
		})
		assert.NoError(t, err, "normalizing anyone counterparty should not error")
		assert.Equal(t, anyonePublicKey.ToDERHex(), normalized.ToDERHex(), "normalized anyone counterparty should be anyone public key")
	})

	t.Run("should normalize counterparty correctly when given as a public key", func(t *testing.T) {
		normalized, err := keyDeriver.normalizeCounterparty(Counterparty{
			Type:         CounterpartyTypeOther,
			Counterparty: counterpartyPublicKey,
		})
		assert.NoError(t, err, "normalizing other counterparty (public key) should not error")
		assert.Equal(t, counterpartyPublicKey.ToDERHex(), normalized.ToDERHex(), "normalized other counterparty should be the provided public key")
	})

	t.Run("should allow public key derivation as anyone", func(t *testing.T) {
		anyoneDeriver := NewKeyDeriver(nil)
		derivedPublicKey, err := anyoneDeriver.DerivePublicKey(
			protocolID,
			keyID,
			Counterparty{
				Type:         CounterpartyTypeOther,
				Counterparty: counterpartyPublicKey,
			},
			false,
		)
		assert.NoError(t, err, "deriving public key as anyone should not error")
		assert.IsType(t, &ec.PublicKey{}, derivedPublicKey, "derived key should be a public key")
	})

	t.Run("should derive the correct public key for counterparty", func(t *testing.T) {
		derivedPublicKey, err := keyDeriver.DerivePublicKey(
			protocolID,
			keyID,
			Counterparty{
				Type:         CounterpartyTypeOther,
				Counterparty: counterpartyPublicKey,
			},
			false,
		)
		assert.NoError(t, err, "deriving public key for counterparty should not error")
		assert.IsType(t, &ec.PublicKey{}, derivedPublicKey, "derived key should be a public key")
	})

	t.Run("should derive the correct public key for self", func(t *testing.T) {
		derivedPublicKey, err := keyDeriver.DerivePublicKey(
			protocolID,
			keyID,
			Counterparty{
				Type:         CounterpartyTypeOther,
				Counterparty: counterpartyPublicKey,
			},
			true,
		)
		assert.NoError(t, err, "deriving public key for self should not error")
		assert.IsType(t, &ec.PublicKey{}, derivedPublicKey, "derived key should be a public key")
	})

	t.Run("should derive the correct private key", func(t *testing.T) {
		derivedPrivateKey, err := keyDeriver.DerivePrivateKey(
			protocolID,
			keyID,
			Counterparty{
				Type:         CounterpartyTypeOther,
				Counterparty: counterpartyPublicKey,
			},
		)
		assert.NoError(t, err, "deriving private key should not error")
		assert.IsType(t, &ec.PrivateKey{}, derivedPrivateKey, "derived key should be a private key")
	})

	t.Run("should derive the correct symmetric key", func(t *testing.T) {
		derivedSymmetricKey, err := keyDeriver.DeriveSymmetricKey(
			protocolID,
			keyID,
			Counterparty{
				Type:         CounterpartyTypeOther,
				Counterparty: counterpartyPublicKey,
			},
		)
		assert.NoError(t, err, "deriving symmetric key should not error")
		assert.NotEmpty(t, derivedSymmetricKey, "derived symmetric key should not be empty")
		assert.Equal(t, "4ce8e868f2006e3fa8fc61ea4bc4be77d397b412b44b4dca047fb7ec3ca7cfd8", hex.EncodeToString(derivedSymmetricKey.ToBytes()), "derived symmetric key should match expected value")
	})

	t.Run("should be able to derive symmetric key with anyone", func(t *testing.T) {
		_, err := keyDeriver.DeriveSymmetricKey(
			protocolID,
			keyID,
			Counterparty{
				Type: CounterpartyTypeAnyone,
			},
		)
		assert.NoError(t, err, "deriving symmetric key with anyone should not error")
	})

	t.Run("should reveal the correct counterparty shared secret", func(t *testing.T) {
		sharedSecret, err := keyDeriver.DeriveSymmetricKey(
			protocolID,
			keyID,
			Counterparty{
				Type:         CounterpartyTypeOther,
				Counterparty: counterpartyPublicKey,
			},
		)
		assert.NoError(t, err, "deriving symmetric key for shared secret test should not error")
		assert.NotEmpty(t, sharedSecret, "shared secret should not be empty")
	})

	t.Run("should not reveal shared secret for self", func(t *testing.T) {
		_, err := keyDeriver.RevealCounterpartySecret(Counterparty{
			Type: CounterpartyTypeSelf,
		})
		assert.EqualError(t, err, "counterparty secrets cannot be revealed for counterparty=self", "revealing secret for self should error")

		_, err = keyDeriver.RevealCounterpartySecret(Counterparty{
			Type:         CounterpartyTypeOther,
			Counterparty: rootPublicKey,
		})
		assert.EqualError(t, err, "counterparty secrets cannot be revealed if counterparty key is self", "revealing secret for self (via public key) should error")
	})

	t.Run("should reveal the correct counterparty shared secret", func(t *testing.T) {
		sharedSecret, err := keyDeriver.RevealCounterpartySecret(Counterparty{
			Type:         CounterpartyTypeOther,
			Counterparty: counterpartyPublicKey,
		})
		assert.NoError(t, err, "revealing counterparty secret should not error")
		assert.NotEmpty(t, sharedSecret, "revealed shared secret should not be empty")

		expected, err := rootPrivateKey.DeriveSharedSecret(counterpartyPublicKey)
		assert.NoError(t, err, "deriving expected shared secret should not error")
		assert.Equal(t, expected.ToDER(), sharedSecret.ToDER(), "revealed shared secret should match expected value")
	})

	t.Run("should reveal the specific key association", func(t *testing.T) {
		secret, err := keyDeriver.RevealSpecificSecret(
			Counterparty{
				Type:         CounterpartyTypeOther,
				Counterparty: counterpartyPublicKey,
			},
			protocolID,
			keyID,
		)
		assert.NoError(t, err, "revealing specific secret should not error")
		assert.NotEmpty(t, secret, "revealed specific secret should not be empty")

		// Verify HMAC computation
		sharedSecret, err := rootPrivateKey.DeriveSharedSecret(counterpartyPublicKey)
		assert.NoError(t, err, "deriving shared secret for verification should not error")

		invoiceNumber, err := keyDeriver.computeInvoiceNumber(protocolID, keyID)
		assert.NoError(t, err, "computing invoice number for verification should not error")

		mac := hmac.New(sha256.New, sharedSecret.X.Bytes())
		mac.Write([]byte(invoiceNumber))
		expected := mac.Sum(nil)

		assert.Equal(t, expected, secret, "revealed specific secret should match computed HMAC")
	})

	t.Run("should throw an error for invalid protocol names", func(t *testing.T) {
		testCases := []struct {
			name     string
			protocol Protocol
			keyID    string
		}{
			{
				name: "long key ID",
				protocol: Protocol{
					SecurityLevel: 2,
					Protocol:      "test",
				},
				keyID: "long" + string(make([]byte, 800)),
			},
			{
				name: "empty key ID",
				protocol: Protocol{
					SecurityLevel: 2,
					Protocol:      "test",
				},
				keyID: "",
			},
			{
				name: "invalid security level",
				protocol: Protocol{
					SecurityLevel: -3,
					Protocol:      "otherwise valid",
				},
				keyID: keyID,
			},
			{
				name: "double space in protocol name",
				protocol: Protocol{
					SecurityLevel: 2,
					Protocol:      "double  space",
				},
				keyID: keyID,
			},
			{
				name: "empty protocol name",
				protocol: Protocol{
					SecurityLevel: 0,
					Protocol:      "",
				},
				keyID: keyID,
			},
			{
				name: "long protocol name",
				protocol: Protocol{
					SecurityLevel: 0,
					Protocol:      "long" + string(make([]byte, 400)),
				},
				keyID: keyID,
			},
			{
				name: "redundant protocol suffix",
				protocol: Protocol{
					SecurityLevel: 2,
					Protocol:      "redundant protocol protocol",
				},
				keyID: keyID,
			},
			{
				name: "invalid characters in protocol name",
				protocol: Protocol{
					SecurityLevel: 2,
					Protocol:      "üñî√é®sål ©0på",
				},
				keyID: keyID,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := keyDeriver.computeInvoiceNumber(tc.protocol, tc.keyID)
				assert.Error(t, err, "computing invoice number with invalid input should error predictably")
			})
		}
	})
}
