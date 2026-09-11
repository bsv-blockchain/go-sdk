package compat

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// TestDecryptSharedBase64Error covers the base64-decode failure branch of DecryptShared.
func TestDecryptSharedBase64Error(t *testing.T) {
	t.Parallel()

	priv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	_, err = DecryptShared("!!!not-valid-base64!!!", priv, priv.PubKey())
	require.Error(t, err)
}

// TestDecryptSharedElectrumError covers the branch where DecryptShared decodes valid
// base64 but ElectrumDecrypt rejects the (too short) payload.
func TestDecryptSharedElectrumError(t *testing.T) {
	t.Parallel()

	priv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	short := base64.StdEncoding.EncodeToString(make([]byte, 10))
	_, err = DecryptShared(short, priv, priv.PubKey())
	require.Error(t, err)
}

// TestElectrumDecryptErrors covers the guarded failure branches of ElectrumDecrypt.
func TestElectrumDecryptErrors(t *testing.T) {
	t.Parallel()

	priv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	validPub := priv.PubKey().Compressed()

	t.Run("too short", func(t *testing.T) {
		t.Parallel()
		_, err := ElectrumDecrypt(make([]byte, 10), priv, nil)
		require.ErrorContains(t, err, "length")
	})

	t.Run("invalid magic bytes", func(t *testing.T) {
		t.Parallel()
		data := make([]byte, 60) // long enough, but no BIE1 prefix
		_, err := ElectrumDecrypt(data, priv, nil)
		require.ErrorContains(t, err, "magic")
	})

	t.Run("invalid ephemeral public key", func(t *testing.T) {
		t.Parallel()
		data := make([]byte, 52)
		copy(data, "BIE1")
		for i := 4; i < 37; i++ {
			data[i] = 0xff // not a valid curve point
		}
		_, err := ElectrumDecrypt(data, priv, nil)
		require.Error(t, err)
	})

	t.Run("mac mismatch", func(t *testing.T) {
		t.Parallel()
		// BIE1 + valid ephemeral pubkey (33) + cipher (16) + wrong mac (32).
		data := append([]byte("BIE1"), validPub...)
		data = append(data, make([]byte, 16)...) // cipher text placeholder
		data = append(data, make([]byte, 32)...) // incorrect mac
		_, err := ElectrumDecrypt(data, priv, nil)
		require.ErrorContains(t, err, "incorrect password")
	})
}

// TestBitcoreDecryptErrors covers the guarded failure branches of BitcoreDecrypt.
func TestBitcoreDecryptErrors(t *testing.T) {
	t.Parallel()

	priv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	other, err := ec.NewPrivateKey()
	require.NoError(t, err)

	t.Run("invalid sender public key", func(t *testing.T) {
		t.Parallel()
		data := make([]byte, 85)
		for i := 0; i < 33; i++ {
			data[i] = 0xff // not a valid curve point
		}
		_, err := BitcoreDecrypt(data, priv)
		require.Error(t, err)
	})

	t.Run("hmac mismatch", func(t *testing.T) {
		t.Parallel()
		// valid sender pubkey (33) + cipher (20) + wrong mac (32).
		data := append([]byte{}, other.PubKey().ToDER()...)
		data = append(data, make([]byte, 20)...) // cipher text placeholder
		data = append(data, make([]byte, 32)...) // incorrect mac
		_, err := BitcoreDecrypt(data, priv)
		require.ErrorContains(t, err, "HMAC mismatch")
	})
}
