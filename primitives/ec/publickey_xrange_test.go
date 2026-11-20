package primitives

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// A compressed key whose X is not below the field prime is not a valid key.
// libsecp256k1 rejects it, and the uncompressed form is already rejected here.
// Before the check, such an X was read modulo P, so p+1, p+2 and p+3 parsed as
// the keys with X = 1, 2 and 3 and kept X >= P.
func TestParsePubKeyCompressedRejectsXNotBelowP(t *testing.T) {
	p := S256().P
	seven := big.NewInt(7)

	// onCurve reports whether x (taken mod p) has a point, using math/big only.
	onCurve := func(x *big.Int) bool {
		rhs := new(big.Int).Exp(x, big.NewInt(3), p)
		rhs.Add(rhs, seven).Mod(rhs, p)
		return rhs.Sign() == 0 || new(big.Int).ModSqrt(rhs, p) != nil
	}

	encode := func(prefix byte, x *big.Int) []byte {
		b := make([]byte, 33)
		b[0] = prefix
		x.FillBytes(b[1:])
		return b
	}

	rejected := 0
	for k := int64(0); k < 64; k++ {
		x := new(big.Int).Add(p, big.NewInt(k))
		if x.BitLen() > 256 {
			break
		}
		// Only x values whose reduction has a point can be mistaken for a key.
		if !onCurve(new(big.Int).Mod(x, p)) {
			continue
		}
		for _, prefix := range []byte{0x02, 0x03} {
			_, err := ParsePubKey(encode(prefix, x))
			require.Error(t, err, "x = p+%d with prefix %#x must be rejected", k, prefix)
			rejected++
		}
	}
	require.Positive(t, rejected, "no on-curve x >= p was exercised")

	// X = p-3 and p-4 are valid and below p: still accepted (the field value of
	// the largest valid x must not be mistaken for an overflow).
	for _, k := range []int64{3, 4} {
		x := new(big.Int).Sub(p, big.NewInt(k))
		require.True(t, onCurve(x))
		for _, prefix := range []byte{0x02, 0x03} {
			key, err := ParsePubKey(encode(prefix, x))
			require.NoError(t, err)
			require.Equal(t, 0, key.X.Cmp(x))
		}
	}
}
