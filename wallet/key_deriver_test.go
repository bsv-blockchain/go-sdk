package wallet_test

import (
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"testing"

	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
)

func TestKeyDeriver(t *testing.T) {
	rootPrivateKey, _ := ec.NewPrivateKey()
	rootPublicKey := rootPrivateKey.PubKey()
	counterpartyPrivateKey, _ := ec.NewPrivateKey()
	counterpartyPublicKey := counterpartyPrivateKey.PubKey()
	anyonePrivateKey, _ := ec.PrivateKeyFromBytes([]byte{1})
	anyonePublicKey := anyonePrivateKey.PubKey()

	protocolID := wallet.WalletProtocol{
		SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
		Protocol:      "testprotocol",
	}
	keyID := "12345"

	var keyDeriver *wallet.KeyDeriver

	t.Run("should compute the correct invoice number", func(t *testing.T) {
		keyDeriver = wallet.NewKeyDeriver(rootPrivateKey)
		invoiceNumber, err := keyDeriver.ComputeInvoiceNumber(protocolID, keyID)
		assert.NoError(t, err)
		assert.Equal(t, "2-testprotocol-12345", invoiceNumber)
	})

	t.Run("should normalize counterparty correctly for self", func(t *testing.T) {
		normalized := keyDeriver.NormalizeCounterparty(wallet.WalletCounterparty{
			Type: wallet.CounterpartyTypeSelf,
		})
		assert.Equal(t, rootPublicKey.ToDERHex(), normalized.ToDERHex())
	})

	t.Run("should normalize counterparty correctly for anyone", func(t *testing.T) {
		normalized := keyDeriver.NormalizeCounterparty(wallet.WalletCounterparty{
			Type: wallet.CounterpartyTypeAnyone,
		})
		assert.Equal(t, anyonePublicKey.ToDERHex(), normalized.ToDERHex())
	})

	t.Run("should normalize counterparty correctly when given as a public key", func(t *testing.T) {
		normalized := keyDeriver.NormalizeCounterparty(wallet.WalletCounterparty{
			Type:         wallet.CounterpartyTypeOther,
			Counterparty: counterpartyPublicKey,
		})
		assert.Equal(t, counterpartyPublicKey.ToDERHex(), normalized.ToDERHex())
	})

	t.Run("should allow public key derivation as anyone", func(t *testing.T) {
		anyoneDeriver := wallet.NewKeyDeriver(anyonePrivateKey)
		derivedPublicKey, err := anyoneDeriver.DerivePublicKey(
			protocolID,
			keyID,
			wallet.WalletCounterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: counterpartyPublicKey,
			},
			false,
		)
		assert.NoError(t, err)
		assert.IsType(t, &ec.PublicKey{}, derivedPublicKey)
	})

	t.Run("should derive the correct public key for counterparty", func(t *testing.T) {
		derivedPublicKey, err := keyDeriver.DerivePublicKey(
			protocolID,
			keyID,
			wallet.WalletCounterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: counterpartyPublicKey,
			},
			false,
		)
		assert.NoError(t, err)
		assert.IsType(t, &ec.PublicKey{}, derivedPublicKey)
	})

	t.Run("should derive the correct public key for self", func(t *testing.T) {
		derivedPublicKey, err := keyDeriver.DerivePublicKey(
			protocolID,
			keyID,
			wallet.WalletCounterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: counterpartyPublicKey,
			},
			true,
		)
		assert.NoError(t, err)
		assert.IsType(t, &ec.PublicKey{}, derivedPublicKey)
	})

	t.Run("should derive the correct private key", func(t *testing.T) {
		derivedPrivateKey, err := keyDeriver.DerivePrivateKey(
			protocolID,
			keyID,
			wallet.WalletCounterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: counterpartyPublicKey,
			},
		)
		assert.NoError(t, err)
		assert.IsType(t, &ec.PrivateKey{}, derivedPrivateKey)
	})

	t.Run("should derive the correct symmetric key", func(t *testing.T) {
		derivedSymmetricKey, err := keyDeriver.DeriveSymmetricKey(
			protocolID,
			keyID,
			wallet.WalletCounterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: counterpartyPublicKey,
			},
		)
		assert.NoError(t, err)
		assert.NotEmpty(t, derivedSymmetricKey)
	})

	t.Run("should be able to derive symmetric key with anyone", func(t *testing.T) {
		_, err := keyDeriver.DeriveSymmetricKey(
			protocolID,
			keyID,
			wallet.WalletCounterparty{
				Type: wallet.CounterpartyTypeAnyone,
			},
		)
		assert.NoError(t, err)
	})

	t.Run("should reveal the correct counterparty shared secret", func(t *testing.T) {
		sharedSecret, err := keyDeriver.DeriveSymmetricKey(
			protocolID,
			keyID,
			wallet.WalletCounterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: counterpartyPublicKey,
			},
		)
		assert.NoError(t, err)
		assert.NotEmpty(t, sharedSecret)
	})

	t.Run("should not reveal shared secret for self", func(t *testing.T) {
		_, err := keyDeriver.DeriveSymmetricKey(
			protocolID,
			keyID,
			wallet.WalletCounterparty{
				Type: wallet.CounterpartyTypeSelf,
			},
		)
		assert.Error(t, err)
		assert.EqualError(t, err, "cannot derive symmetric key for self")
	})

	t.Run("should reveal the specific key association", func(t *testing.T) {
		sharedSecret, err := keyDeriver.DeriveSymmetricKey(
			protocolID,
			keyID,
			wallet.WalletCounterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: counterpartyPublicKey,
			},
		)
		assert.NoError(t, err)
		assert.NotEmpty(t, sharedSecret)
	})

	t.Run("should throw an error for invalid protocol names", func(t *testing.T) {
		testCases := []struct {
			name        string
			protocol    wallet.WalletProtocol
			keyID       string
			expectError bool
		}{
			{
				name: "long key ID",
				protocol: wallet.WalletProtocol{
					SecurityLevel: 2,
					Protocol:      "test",
				},
				keyID:       "long" + string(make([]byte, 800)),
				expectError: true,
			},
			{
				name: "empty key ID",
				protocol: wallet.WalletProtocol{
					SecurityLevel: 2,
					Protocol:      "test",
				},
				keyID:       "",
				expectError: true,
			},
			{
				name: "invalid security level",
				protocol: wallet.WalletProtocol{
					SecurityLevel: -3,
					Protocol:      "otherwise valid",
				},
				keyID:       keyID,
				expectError: true,
			},
			{
				name: "double space in protocol name",
				protocol: wallet.WalletProtocol{
					SecurityLevel: 2,
					Protocol:      "double  space",
				},
				keyID:       keyID,
				expectError: true,
			},
			{
				name: "empty protocol name",
				protocol: wallet.WalletProtocol{
					SecurityLevel: 0,
					Protocol:      "",
				},
				keyID:       keyID,
				expectError: true,
			},
			{
				name: "long protocol name",
				protocol: wallet.WalletProtocol{
					SecurityLevel: 0,
					Protocol:      "long" + string(make([]byte, 400)),
				},
				keyID:       keyID,
				expectError: true,
			},
			{
				name: "redundant protocol suffix",
				protocol: wallet.WalletProtocol{
					SecurityLevel: 2,
					Protocol:      "redundant protocol protocol",
				},
				keyID:       keyID,
				expectError: true,
			},
			{
				name: "invalid characters in protocol name",
				protocol: wallet.WalletProtocol{
					SecurityLevel: 2,
					Protocol:      "üñî√é®sål ©0på",
				},
				keyID:       keyID,
				expectError: true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := keyDeriver.ComputeInvoiceNumber(tc.protocol, tc.keyID)
				if tc.expectError {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})
}
