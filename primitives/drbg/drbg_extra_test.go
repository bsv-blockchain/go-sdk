package primitives

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReseed covers the Reseed function which had 0% coverage
func TestReseed(t *testing.T) {
	entropy := make([]byte, 32)
	for i := range entropy {
		entropy[i] = byte(i + 1)
	}
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(i + 0x10)
	}

	t.Run("reseed with sufficient entropy resets reseed counter", func(t *testing.T) {
		drbg, err := NewDRBG(entropy, nonce)
		require.NoError(t, err)

		// Generate a few values to advance the counter
		_, err = drbg.Generate(32)
		require.NoError(t, err)
		_, err = drbg.Generate(32)
		require.NoError(t, err)

		// Counter should be 3 at this point (starts at 1, increments per Generate)
		assert.Equal(t, 3, drbg.ReseedCounter)

		// Reseed with new entropy
		newEntropy := make([]byte, 32)
		for i := range newEntropy {
			newEntropy[i] = byte(i + 0x80)
		}
		err = drbg.Reseed(newEntropy)
		require.NoError(t, err)

		// Counter should be reset to 1
		assert.Equal(t, 1, drbg.ReseedCounter)
	})

	t.Run("reseed changes the output of subsequent Generate calls", func(t *testing.T) {
		drbg, err := NewDRBG(entropy, nonce)
		require.NoError(t, err)

		before, err := drbg.Generate(32)
		require.NoError(t, err)

		// Re-create identical DRBG and reseed it with different entropy
		drbg2, err := NewDRBG(entropy, nonce)
		require.NoError(t, err)

		// Consume one generate to reach same state
		_, err = drbg2.Generate(32)
		require.NoError(t, err)

		// Now reseed with different entropy
		differentEntropy := make([]byte, 32)
		for i := range differentEntropy {
			differentEntropy[i] = byte(i + 0xAA)
		}
		err = drbg2.Reseed(differentEntropy)
		require.NoError(t, err)

		after, err := drbg2.Generate(32)
		require.NoError(t, err)

		// After reseeding with different entropy, output should differ from original
		assert.NotEqual(t, before, after)
	})

	t.Run("reseed fails when entropy is less than 32 bytes", func(t *testing.T) {
		drbg, err := NewDRBG(entropy, nonce)
		require.NoError(t, err)

		shortEntropy := make([]byte, 16) // less than 32
		err = drbg.Reseed(shortEntropy)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not enough entropy")
	})

	t.Run("reseed with exactly 32 bytes succeeds", func(t *testing.T) {
		drbg, err := NewDRBG(entropy, nonce)
		require.NoError(t, err)

		exactEntropy := make([]byte, 32)
		for i := range exactEntropy {
			exactEntropy[i] = byte(i + 0x55)
		}
		err = drbg.Reseed(exactEntropy)
		require.NoError(t, err)
		assert.Equal(t, 1, drbg.ReseedCounter)
	})

	t.Run("reseed updates K and V fields", func(t *testing.T) {
		drbg, err := NewDRBG(entropy, nonce)
		require.NoError(t, err)

		oldK := make([]byte, len(drbg.K))
		oldV := make([]byte, len(drbg.V))
		copy(oldK, drbg.K)
		copy(oldV, drbg.V)

		newEntropy := make([]byte, 32)
		for i := range newEntropy {
			newEntropy[i] = byte(0xFF - i)
		}
		err = drbg.Reseed(newEntropy)
		require.NoError(t, err)

		assert.NotEqual(t, oldK, drbg.K, "K should change after reseed")
		assert.NotEqual(t, oldV, drbg.V, "V should change after reseed")
	})
}

// TestDRBG_GenerateEdgeCases covers Generate error paths
func TestDRBG_GenerateEdgeCases(t *testing.T) {
	entropy := make([]byte, 32)
	for i := range entropy {
		entropy[i] = byte(i + 1)
	}

	t.Run("generate fails when reseed counter exceeds 10000", func(t *testing.T) {
		drbg, err := NewDRBG(entropy, nil)
		require.NoError(t, err)

		// Manually set the counter above the threshold
		drbg.ReseedCounter = 10001

		_, err = drbg.Generate(32)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reseed required")
	})

	t.Run("generate fails when request is too large", func(t *testing.T) {
		drbg, err := NewDRBG(entropy, nil)
		require.NoError(t, err)

		_, err = drbg.Generate(938) // MaxBytesPerGenerate is 937
		require.Error(t, err)
		assert.Contains(t, err.Error(), "request too large")
	})

	t.Run("generate exactly at max bytes succeeds", func(t *testing.T) {
		drbg, err := NewDRBG(entropy, nil)
		require.NoError(t, err)

		result, err := drbg.Generate(937)
		require.NoError(t, err)
		assert.Len(t, result, 937)
	})
}

// TestNewDRBG_InsufficientEntropy covers the error path for NewDRBG
func TestNewDRBG_InsufficientEntropy(t *testing.T) {
	shortEntropy := make([]byte, 16) // less than 32 bytes
	_, err := NewDRBG(shortEntropy, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not enough entropy")
}
