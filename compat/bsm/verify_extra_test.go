package compat_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	compat "github.com/bsv-blockchain/go-sdk/compat/bsm"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// TestVerifyMessageDERInvalidPublicKey covers the branch where the signature is valid
// DER but the supplied public key hex does not parse as a valid point.
func TestVerifyMessageDERInvalidPublicKey(t *testing.T) {
	t.Parallel()

	// Produce a valid strict-DER signature over an arbitrary hash.
	pk, err := ec.NewPrivateKey()
	require.NoError(t, err)
	var hash [32]byte
	sig, err := pk.Sign(hash[:])
	require.NoError(t, err)
	sigHex := hex.EncodeToString(sig.Serialize())

	// A well-formed hex string that is not a valid compressed public key point.
	badPubKey := "02" + "ff00000000000000000000000000000000000000000000000000000000000000"

	verified, err := compat.VerifyMessageDER(hash, badPubKey, sigHex)
	require.Error(t, err)
	require.False(t, verified)
}
