package compat_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	compat "github.com/bsv-blockchain/go-sdk/compat/bip32"
)

// TestGetExtendedPublicKeyNeuterError covers the error branch of GetExtendedPublicKey
// when the underlying key has an unmappable (invalid) private version and Neuter fails.
func TestGetExtendedPublicKeyNeuterError(t *testing.T) {
	t.Parallel()

	k := compat.NewExtendedKey([]byte{0x01, 0x02, 0x03, 0x04}, make([]byte, 32), make([]byte, 32), []byte{0, 0, 0, 0}, 0, 0, true)
	_, err := compat.GetExtendedPublicKey(k)
	require.Error(t, err)
}
