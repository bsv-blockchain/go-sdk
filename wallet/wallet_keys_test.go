package wallet

import (
	"encoding/hex"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	knownPrivBytes            = []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32}
	knownPrivKey, knownPubKey = ec.PrivateKeyFromBytes(knownPrivBytes)
	knownPrivKeyHex           = hex.EncodeToString(knownPrivBytes)
	knownPubKeyHex            = knownPubKey.ToDERHex()
	knownKeyDeriver           = NewKeyDeriver(knownPrivKey)
	knownWIF                  = WIF(knownPrivKey.Wif())
)

func TestToPrivateKey(t *testing.T) {
	t.Run("string hex input", func(t *testing.T) {
		// when:
		privKey, err := ToPrivateKey(knownPrivKeyHex)

		// then:
		require.NoError(t, err)
		require.NotNil(t, privKey)
		assert.Equal(t, knownPrivKey.Serialize(), privKey.Serialize())
	})

	t.Run("WIF input", func(t *testing.T) {
		// when:
		privKey, err := ToPrivateKey(knownWIF)

		// then:
		require.NoError(t, err)
		require.NotNil(t, privKey)
		assert.Equal(t, knownPrivKey.Serialize(), privKey.Serialize())
	})

	t.Run("*ec.PrivateKey input", func(t *testing.T) {
		// when:
		privKey, err := ToPrivateKey(knownPrivKey)

		// then:
		require.NoError(t, err)
		require.NotNil(t, privKey)
		assert.Equal(t, knownPrivKey, privKey)
	})

	t.Run("nil *ec.PrivateKey input", func(t *testing.T) {
		// when:
		var nilPrivKey *ec.PrivateKey = nil
		privKey, err := ToPrivateKey(nilPrivKey)

		// then:
		assert.Error(t, err)
		assert.Nil(t, privKey)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("invalid hex string", func(t *testing.T) {
		// when:
		privKey, err := ToPrivateKey("not a valid hex string")

		// then:
		assert.Error(t, err)
		assert.Nil(t, privKey)
		assert.Contains(t, err.Error(), "failed to parse private key from string hex")
	})

	t.Run("invalid WIF", func(t *testing.T) {
		// when:
		privKey, err := ToPrivateKey(WIF("invalid wif"))

		// then:
		assert.Error(t, err)
		assert.Nil(t, privKey)
		assert.Contains(t, err.Error(), "failed to parse private key from string containing WIF")
	})
}

// TestToKeyDeriver tests the ToKeyDeriver function
func TestToKeyDeriver(t *testing.T) {
	t.Run("string hex input", func(t *testing.T) {
		// when:
		keyDeriver, err := ToKeyDeriver(knownPrivKeyHex)

		// then:
		require.NoError(t, err)
		require.NotNil(t, keyDeriver)
		assert.Equal(t, knownKeyDeriver.IdentityKeyHex(), keyDeriver.IdentityKeyHex())
	})

	t.Run("WIF input", func(t *testing.T) {
		// when:
		keyDeriver, err := ToKeyDeriver(knownWIF)

		// then:
		require.NoError(t, err)
		require.NotNil(t, keyDeriver)
		assert.Equal(t, knownKeyDeriver.IdentityKeyHex(), keyDeriver.IdentityKeyHex())
	})

	t.Run("*ec.PrivateKey input", func(t *testing.T) {
		// when:
		keyDeriver, err := ToKeyDeriver(knownPrivKey)

		// then:
		require.NoError(t, err)
		require.NotNil(t, keyDeriver)
		assert.Equal(t, knownKeyDeriver.IdentityKeyHex(), keyDeriver.IdentityKeyHex())
	})

	t.Run("*KeyDeriver input", func(t *testing.T) {
		// when:
		keyDeriver, err := ToKeyDeriver(knownKeyDeriver)

		// then:
		require.NoError(t, err)
		require.NotNil(t, keyDeriver)
		assert.Equal(t, knownKeyDeriver, keyDeriver)
	})

	t.Run("nil *ec.PrivateKey input", func(t *testing.T) {
		// when:
		var nilPrivKey *ec.PrivateKey = nil
		keyDeriver, err := ToKeyDeriver(nilPrivKey)

		// then:
		assert.Error(t, err)
		assert.Nil(t, keyDeriver)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("nil *KeyDeriver input", func(t *testing.T) {
		// when:
		var nilKeyDeriver *KeyDeriver = nil
		keyDeriver, err := ToKeyDeriver(nilKeyDeriver)

		// then:
		assert.Error(t, err)
		assert.Nil(t, keyDeriver)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("invalid hex string", func(t *testing.T) {
		// when:
		keyDeriver, err := ToKeyDeriver("not a valid hex string")

		// then:
		assert.Error(t, err)
		assert.Nil(t, keyDeriver)
		assert.Contains(t, err.Error(), "failed to parse private key from string hex")
	})

	t.Run("invalid WIF", func(t *testing.T) {
		// when:
		keyDeriver, err := ToKeyDeriver(WIF("invalid wif"))

		// then:
		assert.Error(t, err)
		assert.Nil(t, keyDeriver)
		assert.Contains(t, err.Error(), "failed to parse private key from string containing WIF")
	})
}

func TestToIdentityKey(t *testing.T) {
	t.Run("string input", func(t *testing.T) {
		// when:
		pubKey, err := ToIdentityKey(knownPubKeyHex)

		// then:
		require.NoError(t, err)
		require.NotNil(t, pubKey)
		assert.Equal(t, knownPubKeyHex, pubKey.ToDERHex())
	})

	t.Run("WIF input", func(t *testing.T) {
		// when:
		pubKey, err := ToIdentityKey(knownWIF)

		// then:
		require.NoError(t, err)
		require.NotNil(t, pubKey)
		assert.Equal(t, knownPubKeyHex, pubKey.ToDERHex())
	})

	t.Run("*KeyDeriver input", func(t *testing.T) {
		// when:
		pubKey, err := ToIdentityKey(knownKeyDeriver)

		// then:
		require.NoError(t, err)
		require.NotNil(t, pubKey)
		assert.Equal(t, knownPubKeyHex, pubKey.ToDERHex())
	})

	t.Run("*ec.PublicKey input", func(t *testing.T) {
		// when:
		pubKey, err := ToIdentityKey(knownPubKey)

		// then:
		require.NoError(t, err)
		require.NotNil(t, pubKey)
		assert.Equal(t, knownPubKey, pubKey)
	})

	t.Run("nil *KeyDeriver input", func(t *testing.T) {
		// when:
		var nilKeyDeriver *KeyDeriver = nil
		pubKey, err := ToIdentityKey(nilKeyDeriver)

		// then:
		assert.Error(t, err)
		assert.Nil(t, pubKey)
		assert.Contains(t, err.Error(), "key deriver cannot be nil")
	})

	t.Run("nil *ec.PublicKey input", func(t *testing.T) {
		// when:
		var nilPubKey *ec.PublicKey = nil
		pubKey, err := ToIdentityKey(nilPubKey)

		// then:
		assert.Error(t, err)
		assert.Nil(t, pubKey)
		assert.Contains(t, err.Error(), "public key cannot be nil")
	})

	t.Run("invalid string", func(t *testing.T) {
		// when:
		pubKey, err := ToIdentityKey("not a valid public key string")

		// then:
		assert.Error(t, err)
		assert.Nil(t, pubKey)
		assert.Contains(t, err.Error(), "failed to parse public key from string")
	})

	t.Run("invalid WIF", func(t *testing.T) {
		// when:
		pubKey, err := ToIdentityKey(WIF("invalid wif"))

		// then:
		assert.Error(t, err)
		assert.Nil(t, pubKey)
		assert.Contains(t, err.Error(), "failed to parse public key from string containing WIF")
	})
}
