package primitives

import (
	e "crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const errCustomKOutOfRange = "customK is out of valid range"

func makeTestPrivKey(t *testing.T) *e.PrivateKey {
	t.Helper()
	privKeyInt := new(big.Int)
	privKeyInt.SetString(privateHex, 16)
	privateKey := &e.PrivateKey{
		D: privKeyInt,
		PublicKey: e.PublicKey{
			Curve: elliptic.P256(),
		},
	}
	privateKey.X, privateKey.Y = privateKey.ScalarBaseMult(privateKey.D.Bytes())
	return privateKey
}

// TestSignWithCustomKOutOfRangeK covers the error when customK is out of valid range
func TestSignWithCustomKOutOfRangeK(t *testing.T) {
	msg := []byte("test message hash")
	privateKey := makeTestPrivKey(t)

	t.Run("customK = 0 is out of range", func(t *testing.T) {
		_, err := SignWithCustomK(msg, privateKey, false, big.NewInt(0))
		require.Error(t, err)
		assert.Contains(t, err.Error(), errCustomKOutOfRange)
	})

	t.Run("customK = -1 is out of range", func(t *testing.T) {
		_, err := SignWithCustomK(msg, privateKey, false, big.NewInt(-1))
		require.Error(t, err)
		assert.Contains(t, err.Error(), errCustomKOutOfRange)
	})

	t.Run("customK = N (curve order) is out of range", func(t *testing.T) {
		N := privateKey.Curve.Params().N
		_, err := SignWithCustomK(msg, privateKey, false, N)
		require.Error(t, err)
		assert.Contains(t, err.Error(), errCustomKOutOfRange)
	})

	t.Run("customK = N+1 is out of range", func(t *testing.T) {
		N := privateKey.Curve.Params().N
		bigK := new(big.Int).Add(N, big.NewInt(1))
		_, err := SignWithCustomK(msg, privateKey, false, bigK)
		require.Error(t, err)
		assert.Contains(t, err.Error(), errCustomKOutOfRange)
	})
}

// TestSignWithCustomKForceLowS covers the high-S to low-S normalization branch
func TestSignWithCustomKForceLowS(t *testing.T) {
	privateKey := makeTestPrivKey(t)
	msg := []byte("deadbeef message hash")

	// Try various k values until one produces a high-S value so we can test the branch.
	// We know k=1 often produces a high S for this key.
	for k := int64(1); k <= 500; k++ {
		customK := big.NewInt(k)

		// Without forceLowS
		sigNoForce, err := SignWithCustomK(msg, privateKey, false, customK)
		if err != nil {
			continue
		}

		N := privateKey.Curve.Params().N
		halfOrder := new(big.Int).Rsh(N, 1)

		if sigNoForce.S.Cmp(halfOrder) > 0 {
			// Found a k that produces high-S; now verify forceLowS normalises it
			sigForce, err := SignWithCustomK(msg, privateKey, true, customK)
			require.NoError(t, err)
			assert.True(t, sigForce.S.Cmp(halfOrder) <= 0, "forceLowS should produce a low-S value")
			// The two signatures should differ
			assert.NotEqual(t, sigNoForce.S, sigForce.S)
			return
		}
	}
	// If we get here, every k produced low-S (unlikely, but not a failure of the code path).
	t.Skip("could not find a k value that produces high-S for this key/message combo")
}

// TestSign_ForceLowS via top-level Sign with customK=nil covers the low-S branch in Sign
func TestSignForceLowSPath(t *testing.T) {
	privateKey := makeTestPrivKey(t)

	// Run many signatures until we get a high-S value in the random path
	N := privateKey.Curve.Params().N
	halfOrder := new(big.Int).Rsh(N, 1)
	msg := []byte("test message bytes")

	for i := 0; i < 100; i++ {
		sig, err := Sign(msg, privateKey, false, nil)
		require.NoError(t, err)
		if sig.S.Cmp(halfOrder) > 0 {
			// Now sign same message with forceLowS and verify it's low-S
			sigLow, err := Sign(msg, privateKey, true, nil)
			require.NoError(t, err)
			assert.True(t, sigLow.S.Cmp(halfOrder) <= 0)
			return
		}
	}
	// All 100 attempts produced low-S naturally; the branch was exercised by the loop logic above
	t.Log("all random S values were already low; low-S branch may not have been triggered")
}
