package wallet

import (
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/assert"
)

type MockKeyDeriver struct {
	publicKeyCallCount        int
	privateKeyCallCount       int
	symmetricKeyCallCount     int
	specificSecretCallCount   int
	publicKeySleepTime        time.Duration
	publicKeyToReturn         *ec.PublicKey
	privateKeyToReturn        *ec.PrivateKey
	symmetricKeyToReturn      *ec.SymmetricKey
	specificSecretToReturn    []byte
	symmetricKeyErrorToReturn error
}

func (m *MockKeyDeriver) DerivePublicKey(protocolID Protocol, keyID string, counterparty Counterparty, forSelf bool) (*ec.PublicKey, error) {
	if m.publicKeySleepTime > 0 {
		time.Sleep(m.publicKeySleepTime)
	}
	m.publicKeyCallCount++
	return m.publicKeyToReturn, nil
}

func (m *MockKeyDeriver) DerivePrivateKey(protocolID Protocol, keyID string, counterparty Counterparty) (*ec.PrivateKey, error) {
	m.privateKeyCallCount++
	return m.privateKeyToReturn, nil
}

func (m *MockKeyDeriver) DeriveSymmetricKey(protocolID Protocol, keyID string, counterparty Counterparty) (*ec.SymmetricKey, error) {
	m.symmetricKeyCallCount++
	return m.symmetricKeyToReturn, m.symmetricKeyErrorToReturn
}
func (m *MockKeyDeriver) RevealSpecificSecret(counterparty Counterparty, protocol Protocol, keyID string) ([]byte, error) {
	m.specificSecretCallCount++
	return m.specificSecretToReturn, nil
}

func TestDerivePublicKey(t *testing.T) {
	// Create keys and cached key deriver
	rootKey, _ := ec.PrivateKeyFromBytes([]byte{1})
	publicKey := &ec.PublicKey{X: big.NewInt(0), Y: big.NewInt(0), Curve: ec.S256()}

	// Create parameters
	protocol := Protocol{
		SecurityLevel: SecurityLevelSilent,
		Protocol:      "testprotocol",
	}
	keyID := "key1"
	counterparty := Counterparty{
		Type: CounterpartyTypeSelf,
	}

	t.Run("should call derivePublicKey on KeyDeriver and cache the result", func(t *testing.T) {
		// Create a mock key deriver that returns a fixed public key
		cachedDeriver := NewCachedKeyDeriver(rootKey, 0)
		mockKeyDeriver := &MockKeyDeriver{publicKeyToReturn: publicKey}
		cachedDeriver.keyDeriver = mockKeyDeriver

		// First call - should call through to real deriver
		pubKey1, err := cachedDeriver.DerivePublicKey(protocol, keyID, counterparty, false)
		assert.NoError(t, err)
		assert.NotNil(t, pubKey1)
		assert.Equal(t, publicKey.ToDERHex(), pubKey1.ToDERHex())

		// Second call - should return cached value
		pubKey2, err := cachedDeriver.DerivePublicKey(protocol, keyID, counterparty, false)
		assert.NoError(t, err)
		assert.Equal(t, pubKey1.ToDERHex(), pubKey2.ToDERHex())
		assert.Equal(t, mockKeyDeriver.publicKeyCallCount, 1)
	})

	t.Run("should handle different parameters correctly", func(t *testing.T) {
		// Create a mock key deriver that returns a fixed public key
		cachedDeriver := NewCachedKeyDeriver(rootKey, 0)
		mockKeyDeriver := &MockKeyDeriver{publicKeyToReturn: publicKey}
		cachedDeriver.keyDeriver = mockKeyDeriver

		// Call with first set of params
		pubKey1, err := cachedDeriver.DerivePublicKey(Protocol{
			SecurityLevel: SecurityLevelSilent,
			Protocol:      "protocol1",
		}, "key1", Counterparty{
			Type: CounterpartyTypeSelf,
		}, false)
		assert.NoError(t, err)
		assert.Equal(t, publicKey.ToDERHex(), pubKey1.ToDERHex())

		// Call with different params
		pubKey2, err := cachedDeriver.DerivePublicKey(Protocol{
			SecurityLevel: SecurityLevelEveryApp,
			Protocol:      "protocol2",
		}, "key2", Counterparty{
			Type: CounterpartyTypeAnyone,
		}, false)
		assert.NoError(t, err)
		assert.Equal(t, pubKey1.ToDERHex(), pubKey2.ToDERHex())
		assert.Equal(t, mockKeyDeriver.publicKeyCallCount, 2)
	})
}

func TestDerivePrivateKey(t *testing.T) {
	// Create keys and cached key deriver
	rootKey, _ := ec.PrivateKeyFromBytes([]byte{1})

	// Create parameters
	protocol := Protocol{
		SecurityLevel: SecurityLevelEveryApp,
		Protocol:      "testprotocol",
	}
	keyID := "key1"
	counterparty := Counterparty{
		Type: CounterpartyTypeAnyone,
	}

	t.Run("should call derivePrivateKey on KeyDeriver and cache the result", func(t *testing.T) {
		// Generate keys
		privateKey, err := ec.NewPrivateKey()
		assert.NoError(t, err)

		// Create a mock key deriver that returns a fixed private key
		cachedDeriver := NewCachedKeyDeriver(rootKey, 0)
		mockKeyDeriver := &MockKeyDeriver{privateKeyToReturn: privateKey}
		cachedDeriver.keyDeriver = mockKeyDeriver

		// First call - should call through to real deriver
		privKey1, err := cachedDeriver.DerivePrivateKey(protocol, keyID, counterparty)
		assert.NoError(t, err)
		assert.Equal(t, privateKey.Wif(), privKey1.Wif())

		// Second call - should return cached value
		privKey2, err := cachedDeriver.DerivePrivateKey(protocol, keyID, counterparty)
		assert.NoError(t, err)
		assert.Equal(t, privKey1.Wif(), privKey2.Wif())
		assert.Equal(t, mockKeyDeriver.privateKeyCallCount, 1)
	})

	t.Run("should differentiate cache entries based on parameters", func(t *testing.T) {
		// Generate keys
		privateKey, err := ec.NewPrivateKey()
		assert.NoError(t, err)
		privateKey2, err := ec.NewPrivateKey()
		assert.NoError(t, err)

		// Create a mock key deriver that returns a fixed private key
		cachedDeriver := NewCachedKeyDeriver(rootKey, 0)
		mockKeyDeriver := &MockKeyDeriver{privateKeyToReturn: privateKey}
		cachedDeriver.keyDeriver = mockKeyDeriver

		// First call
		privKey1, err := cachedDeriver.DerivePrivateKey(protocol, keyID, counterparty)
		assert.NoError(t, err)
		assert.Equal(t, privateKey.Wif(), privKey1.Wif())

		// Second call with different keyID
		mockKeyDeriver.privateKeyToReturn = privateKey2
		privKey2, err := cachedDeriver.DerivePrivateKey(protocol, "key2", counterparty)
		assert.NoError(t, err)
		assert.Equal(t, privateKey2.Wif(), privKey2.Wif())
		assert.Equal(t, mockKeyDeriver.privateKeyCallCount, 2)

	})
}

func TestDeriveSymmetricKey(t *testing.T) {
	// Create keys and cached key deriver
	rootKey, _ := ec.PrivateKeyFromBytes([]byte{1})
	counterpartyKey := &ec.PublicKey{X: big.NewInt(0), Y: big.NewInt(0), Curve: ec.S256()}

	// Create parameters
	protocol := Protocol{
		SecurityLevel: SecurityLevelEveryAppAndCounterparty,
		Protocol:      "testprotocol",
	}
	keyID := "key1"
	counterparty := Counterparty{
		Type:         CounterpartyTypeOther,
		Counterparty: counterpartyKey,
	}

	t.Run("should call deriveSymmetricKey on KeyDeriver and cache the result", func(t *testing.T) {
		// Generate keys
		symmetricKey := ec.NewSymmetricKeyFromRandom()

		// Create a mock key deriver that returns a fixed symmetric key
		cachedDeriver := NewCachedKeyDeriver(rootKey, 0)
		mockKeyDeriver := &MockKeyDeriver{symmetricKeyToReturn: symmetricKey}
		cachedDeriver.keyDeriver = mockKeyDeriver

		// First call
		symmetricKey1, err := cachedDeriver.DeriveSymmetricKey(protocol, keyID, counterparty)
		assert.NoError(t, err)
		assert.Equal(t, symmetricKey.ToBytes(), symmetricKey1.ToBytes())

		// Second call with same parameters
		symmetricKey2, err := cachedDeriver.DeriveSymmetricKey(protocol, keyID, counterparty)
		assert.NoError(t, err)
		assert.Equal(t, symmetricKey1.ToBytes(), symmetricKey2.ToBytes())
		assert.Equal(t, mockKeyDeriver.symmetricKeyCallCount, 1)
	})

	t.Run("should differentiate cache entries based on parameters", func(t *testing.T) {
		// Generate keys
		symmetricKey1 := ec.NewSymmetricKeyFromRandom()
		symmetricKey2 := ec.NewSymmetricKeyFromRandom()

		// Create a mock key deriver that returns a fixed private key
		cachedDeriver := NewCachedKeyDeriver(rootKey, 0)
		mockKeyDeriver := &MockKeyDeriver{symmetricKeyToReturn: symmetricKey1}
		cachedDeriver.keyDeriver = mockKeyDeriver

		// First call
		result1, err := cachedDeriver.DeriveSymmetricKey(protocol, keyID, counterparty)
		assert.NoError(t, err)
		assert.Equal(t, result1.ToBytes(), symmetricKey1.ToBytes())

		// Second call with different keyID
		mockKeyDeriver.symmetricKeyToReturn = symmetricKey2
		result2, err := cachedDeriver.DeriveSymmetricKey(protocol, "key2", counterparty)
		assert.NoError(t, err)
		assert.Equal(t, result2.ToBytes(), symmetricKey2.ToBytes())
		assert.Equal(t, mockKeyDeriver.symmetricKeyCallCount, 2)
	})

	t.Run("should return an error when KeyDeriver returns an error", func(t *testing.T) {
		const testErrorText = "test error"
		// Create a mock key deriver that returns an error
		cachedDeriver := NewCachedKeyDeriver(rootKey, 0)
		mockKeyDeriver := &MockKeyDeriver{symmetricKeyErrorToReturn: errors.New(testErrorText)}
		cachedDeriver.keyDeriver = mockKeyDeriver

		result1, err := cachedDeriver.DeriveSymmetricKey(protocol, keyID, counterparty)
		assert.Nil(t, result1)
		assert.Error(t, err, testErrorText)
	})
}

func TestCacheManagement(t *testing.T) {
	// Create keys and cached key deriver
	rootKey, _ := ec.PrivateKeyFromBytes([]byte{1})

	t.Run("should not exceed the max cache size and evict least recently used items", func(t *testing.T) {
		maxCacheSize := 5
		cachedDeriver := NewCachedKeyDeriver(rootKey, maxCacheSize)

		// Create mock key deriver that returns unique public keys
		mockKeyDeriver := &MockKeyDeriver{}
		cachedDeriver.keyDeriver = mockKeyDeriver

		protocol := Protocol{SecurityLevel: SecurityLevelSilent, Protocol: "testprotocol"}
		counterparty := Counterparty{Type: CounterpartyTypeSelf}

		// Add entries to fill the cache
		for i := 0; i < maxCacheSize; i++ {
			mockKeyDeriver.publicKeyToReturn = &ec.PublicKey{X: big.NewInt(int64(i)), Y: big.NewInt(0), Curve: ec.S256()}
			_, err := cachedDeriver.DerivePublicKey(protocol, fmt.Sprintf("key%d", i), counterparty, false)
			assert.NoError(t, err)
		}

		// Cache should be full now
		assert.Equal(t, maxCacheSize, cachedDeriver.cache.list.Len())

		// Access one of the earlier keys to make it recently used
		_, err := cachedDeriver.DerivePublicKey(protocol, "key0", counterparty, false)
		assert.NoError(t, err)

		// Add one more entry to exceed the cache size
		mockKeyDeriver.publicKeyToReturn = &ec.PublicKey{X: big.NewInt(int64(maxCacheSize)), Y: big.NewInt(0), Curve: ec.S256()}
		_, err = cachedDeriver.DerivePublicKey(protocol, "key5", counterparty, false)
		assert.NoError(t, err)

		// Cache size should still be maxCacheSize
		assert.Equal(t, maxCacheSize, cachedDeriver.cache.list.Len())

		// The least recently used item (key1) should have been evicted
		// The cache should contain keys: key0, key2, key3, key4, key5
		// Verify by checking cache keys
		cacheKeys := make([]string, 0)
		for elem := cachedDeriver.cache.list.Front(); elem != nil; elem = elem.Next() {
			key := elem.Value.(cacheKey)
			cacheKeys = append(cacheKeys, key.keyID)
		}
		assert.Contains(t, cacheKeys, "key0")
		assert.Contains(t, cacheKeys, "key2")
		assert.Contains(t, cacheKeys, "key3")
		assert.Contains(t, cacheKeys, "key4")
		assert.Contains(t, cacheKeys, "key5")
		assert.Len(t, cacheKeys, maxCacheSize)
	})
}

func TestRevealSpecificSecret(t *testing.T) {
	// Create keys and cached key deriver
	rootKey, _ := ec.PrivateKeyFromBytes([]byte{1})

	t.Run("should call RevealSpecificSecret on KeyDeriver and cache the result", func(t *testing.T) {
		// Create test secret
		testSecret := []byte{4, 5, 6}

		// Create a mock key deriver that returns a fixed secret
		cachedDeriver := NewCachedKeyDeriver(rootKey, 0)
		mockKeyDeriver := &MockKeyDeriver{specificSecretToReturn: testSecret}
		cachedDeriver.keyDeriver = mockKeyDeriver

		// First call - should call through to real deriver
		secret1, err := cachedDeriver.RevealSpecificSecret(
			Counterparty{Type: CounterpartyTypeSelf},
			Protocol{SecurityLevel: SecurityLevelSilent, Protocol: "testprotocol"},
			"key1",
		)
		assert.NoError(t, err)
		assert.Equal(t, testSecret, secret1)
		assert.Equal(t, 1, mockKeyDeriver.specificSecretCallCount)

		// Second call with same parameters - should return cached value
		secret2, err := cachedDeriver.RevealSpecificSecret(
			Counterparty{Type: CounterpartyTypeSelf},
			Protocol{SecurityLevel: SecurityLevelSilent, Protocol: "testprotocol"},
			"key1",
		)
		assert.NoError(t, err)
		assert.Equal(t, secret1, secret2)
		assert.Equal(t, 1, mockKeyDeriver.specificSecretCallCount)
	})

	t.Run("should handle different parameters correctly", func(t *testing.T) {
		// Create test secrets
		secret1 := []byte{4, 5, 6}
		secret2 := []byte{7, 8, 9}

		// Create a mock key deriver that returns different secrets
		cachedDeriver := NewCachedKeyDeriver(rootKey, 0)
		mockKeyDeriver := &MockKeyDeriver{
			specificSecretToReturn: secret1,
		}
		cachedDeriver.keyDeriver = mockKeyDeriver

		// First call
		result1, err := cachedDeriver.RevealSpecificSecret(
			Counterparty{Type: CounterpartyTypeSelf},
			Protocol{SecurityLevel: SecurityLevelSilent, Protocol: "protocol1"},
			"key1",
		)
		assert.NoError(t, err)
		assert.Equal(t, secret1, result1)

		// Second call with different parameters
		mockKeyDeriver.specificSecretToReturn = secret2
		result2, err := cachedDeriver.RevealSpecificSecret(
			Counterparty{Type: CounterpartyTypeSelf},
			Protocol{SecurityLevel: SecurityLevelEveryApp, Protocol: "protocol2"},
			"key2",
		)
		assert.NoError(t, err)
		assert.Equal(t, secret2, result2)
		assert.Equal(t, 2, mockKeyDeriver.specificSecretCallCount)
	})
}

func TestPerformanceConsiderations(t *testing.T) {
	// Create keys and cached key deriver
	rootKey, _ := ec.PrivateKeyFromBytes([]byte{1})

	t.Run("should improve performance by caching expensive operations", func(t *testing.T) {
		protocol := Protocol{SecurityLevel: SecurityLevelSilent, Protocol: "testprotocol"}
		keyID := "key1"
		counterparty := Counterparty{Type: CounterpartyTypeSelf}

		// Create a cached key deriver
		cachedKeyDeriver := NewCachedKeyDeriver(rootKey, 0)
		mockKeyDeriver := &MockKeyDeriver{}
		cachedKeyDeriver.keyDeriver = mockKeyDeriver

		// Simulate an expensive operation (50ms)
		mockKeyDeriver.publicKeySleepTime = 50 * time.Millisecond
		mockKeyDeriver.publicKeyToReturn = &ec.PublicKey{X: big.NewInt(0), Y: big.NewInt(0), Curve: ec.S256()}

		// First call - should be slow
		startTime := time.Now()
		_, err := cachedKeyDeriver.DerivePublicKey(protocol, keyID, counterparty, false)
		assert.NoError(t, err)
		firstCallDuration := time.Since(startTime)

		// Second call - should be fast due to caching
		startTime = time.Now()
		_, err = cachedKeyDeriver.DerivePublicKey(protocol, keyID, counterparty, false)
		assert.NoError(t, err)
		secondCallDuration := time.Since(startTime)

		// Verify performance improvement
		assert.GreaterOrEqual(t, firstCallDuration.Milliseconds(), int64(50))
		assert.Less(t, secondCallDuration.Milliseconds(), int64(10)) // Should be much faster
	})
}
