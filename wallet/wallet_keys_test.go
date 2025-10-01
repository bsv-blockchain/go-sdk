package wallet_test

import (
	"encoding/hex"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	knownPrivBytes            = []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32}
	knownPrivKey, knownPubKey = ec.PrivateKeyFromBytes(knownPrivBytes)
	knownPrivKeyHex           = hex.EncodeToString(knownPrivBytes)
	knownPubKeyHex            = knownPubKey.ToDERHex()
	knownKeyDeriver           = wallet.NewKeyDeriver(knownPrivKey)
	knownWIF                  = wallet.WIF(knownPrivKey.Wif())
)

func TestToPrivateKey(t *testing.T) {
	t.Run("string hex input", func(t *testing.T) {
		// when:
		privKey, err := wallet.ToPrivateKey(wallet.PrivHex(knownPrivKeyHex))

		// then:
		require.NoError(t, err)
		require.NotNil(t, privKey)
		assert.Equal(t, knownPrivKey.Serialize(), privKey.Serialize())
	})

	t.Run("WIF input", func(t *testing.T) {
		// when:
		privKey, err := wallet.ToPrivateKey(knownWIF)

		// then:
		require.NoError(t, err)
		require.NotNil(t, privKey)
		assert.Equal(t, knownPrivKey.Serialize(), privKey.Serialize())
	})

	t.Run("*ec.PrivateKey input", func(t *testing.T) {
		// when:
		privKey, err := wallet.ToPrivateKey(knownPrivKey)

		// then:
		require.NoError(t, err)
		require.NotNil(t, privKey)
		assert.Equal(t, knownPrivKey, privKey)
	})

	t.Run("nil *ec.PrivateKey input", func(t *testing.T) {
		// when:
		var nilPrivKey *ec.PrivateKey = nil
		privKey, err := wallet.ToPrivateKey(nilPrivKey)

		// then:
		assert.Error(t, err)
		assert.Nil(t, privKey)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("invalid hex string", func(t *testing.T) {
		// when:
		privKey, err := wallet.ToPrivateKey(wallet.PrivHex("not a valid hex string"))

		// then:
		assert.Error(t, err)
		assert.Nil(t, privKey)
		assert.Contains(t, err.Error(), "failed to parse private key from string hex")
	})

	t.Run("invalid WIF", func(t *testing.T) {
		// when:
		privKey, err := wallet.ToPrivateKey(wallet.WIF("invalid wif"))

		// then:
		assert.Error(t, err)
		assert.Nil(t, privKey)
		assert.Contains(t, err.Error(), "failed to parse private key from string containing WIF")
	})
}

// TestToKeyDeriver tests the wallet.ToKeyDeriver function
func TestToKeyDeriver(t *testing.T) {
	t.Run("string hex input", func(t *testing.T) {
		// when:
		keyDeriver, err := wallet.ToKeyDeriver(wallet.PrivHex(knownPrivKeyHex))

		// then:
		require.NoError(t, err)
		require.NotNil(t, keyDeriver)
		assert.Equal(t, knownKeyDeriver.IdentityKeyHex(), keyDeriver.IdentityKeyHex())
	})

	t.Run("WIF input", func(t *testing.T) {
		// when:
		keyDeriver, err := wallet.ToKeyDeriver(knownWIF)

		// then:
		require.NoError(t, err)
		require.NotNil(t, keyDeriver)
		assert.Equal(t, knownKeyDeriver.IdentityKeyHex(), keyDeriver.IdentityKeyHex())
	})

	t.Run("*ec.PrivateKey input", func(t *testing.T) {
		// when:
		keyDeriver, err := wallet.ToKeyDeriver(knownPrivKey)

		// then:
		require.NoError(t, err)
		require.NotNil(t, keyDeriver)
		assert.Equal(t, knownKeyDeriver.IdentityKeyHex(), keyDeriver.IdentityKeyHex())
	})

	t.Run("*KeyDeriver input", func(t *testing.T) {
		// when:
		keyDeriver, err := wallet.ToKeyDeriver(knownKeyDeriver)

		// then:
		require.NoError(t, err)
		require.NotNil(t, keyDeriver)
		assert.Equal(t, knownKeyDeriver, keyDeriver)
	})

	t.Run("nil *ec.PrivateKey input", func(t *testing.T) {
		// when:
		var nilPrivKey *ec.PrivateKey = nil
		keyDeriver, err := wallet.ToKeyDeriver(nilPrivKey)

		// then:
		assert.Error(t, err)
		assert.Nil(t, keyDeriver)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("nil *KeyDeriver input", func(t *testing.T) {
		// when:
		var nilKeyDeriver *wallet.KeyDeriver = nil
		keyDeriver, err := wallet.ToKeyDeriver(nilKeyDeriver)

		// then:
		assert.Error(t, err)
		assert.Nil(t, keyDeriver)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("invalid hex string", func(t *testing.T) {
		// when:
		keyDeriver, err := wallet.ToKeyDeriver(wallet.PrivHex("not a valid hex string"))

		// then:
		assert.Error(t, err)
		assert.Nil(t, keyDeriver)
		assert.Contains(t, err.Error(), "failed to parse private key from string hex")
	})

	t.Run("invalid WIF", func(t *testing.T) {
		// when:
		keyDeriver, err := wallet.ToKeyDeriver(wallet.WIF("invalid wif"))

		// then:
		assert.Error(t, err)
		assert.Nil(t, keyDeriver)
		assert.Contains(t, err.Error(), "failed to parse private key from string containing WIF")
	})
}

func TestToIdentityKey(t *testing.T) {
	t.Run("string input", func(t *testing.T) {
		// when:
		pubKey, err := wallet.ToIdentityKey(wallet.PubHex(knownPubKeyHex))

		// then:
		require.NoError(t, err)
		require.NotNil(t, pubKey)
		assert.Equal(t, knownPubKeyHex, pubKey.ToDERHex())
	})

	t.Run("WIF input", func(t *testing.T) {
		// when:
		pubKey, err := wallet.ToIdentityKey(knownWIF)

		// then:
		require.NoError(t, err)
		require.NotNil(t, pubKey)
		assert.Equal(t, knownPubKeyHex, pubKey.ToDERHex())
	})

	t.Run("*KeyDeriver input", func(t *testing.T) {
		// when:
		pubKey, err := wallet.ToIdentityKey(knownKeyDeriver)

		// then:
		require.NoError(t, err)
		require.NotNil(t, pubKey)
		assert.Equal(t, knownPubKeyHex, pubKey.ToDERHex())
	})

	t.Run("*ec.PublicKey input", func(t *testing.T) {
		// when:
		pubKey, err := wallet.ToIdentityKey(knownPubKey)

		// then:
		require.NoError(t, err)
		require.NotNil(t, pubKey)
		assert.Equal(t, knownPubKey, pubKey)
	})

	t.Run("nil *KeyDeriver input", func(t *testing.T) {
		// when:
		var nilKeyDeriver *wallet.KeyDeriver = nil
		pubKey, err := wallet.ToIdentityKey(nilKeyDeriver)

		// then:
		assert.Error(t, err)
		assert.Nil(t, pubKey)
		assert.Contains(t, err.Error(), "key deriver cannot be nil")
	})

	t.Run("nil *ec.PublicKey input", func(t *testing.T) {
		// when:
		var nilPubKey *ec.PublicKey = nil
		pubKey, err := wallet.ToIdentityKey(nilPubKey)

		// then:
		assert.Error(t, err)
		assert.Nil(t, pubKey)
		assert.Contains(t, err.Error(), "public key cannot be nil")
	})

	t.Run("invalid string", func(t *testing.T) {
		// when:
		pubKey, err := wallet.ToIdentityKey(wallet.PubHex("not a valid public key string"))

		// then:
		assert.Error(t, err)
		assert.Nil(t, pubKey)
		assert.Contains(t, err.Error(), "failed to parse public key from string")
	})

	t.Run("invalid WIF", func(t *testing.T) {
		// when:
		pubKey, err := wallet.ToIdentityKey(wallet.WIF("invalid wif"))

		// then:
		assert.Error(t, err)
		assert.Nil(t, pubKey)
		assert.Contains(t, err.Error(), "failed to get public key from WIF")
	})

	t.Run("invalid private key Hex", func(t *testing.T) {
		// when:
		pubKey, err := wallet.ToIdentityKey(wallet.PrivHex("invalid private key hex"))

		// then:
		assert.Error(t, err)
		assert.Nil(t, pubKey)
		assert.Contains(t, err.Error(), "failed to get public key from private key hex")
	})
}
