package compat_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	compat "github.com/bsv-blockchain/go-sdk/compat/bip32"
)

// TestDeriveNumberParseErrors covers the ParseUint failure branches of DeriveNumber
// for the second and third path segments.
func TestDeriveNumberParseErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
	}{
		{name: "second segment not numeric", path: "2147483648/notanumber/2147483648"},
		{name: "third segment not numeric", path: "2147483648/2147483648/notanumber"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := compat.DeriveNumber(tc.path)
			require.Error(t, err)
		})
	}
}

// TestDeriveChildFromPathChildIntOverflow covers the childInt ParseUint failure branch
// (and the wrapping error in DeriveChildFromPath) when a path segment matches the
// numeric-plus-tick pattern but overflows a uint32.
func TestDeriveChildFromPathChildIntOverflow(t *testing.T) {
	t.Parallel()

	k, err := compat.NewKeyFromString(testXPriv)
	require.NoError(t, err)

	_, err = k.DeriveChildFromPath("99999999999999999999")
	require.Error(t, err)
	require.Contains(t, err.Error(), "derive key failed")
}

// TestDeriveChildFromPathChildError covers the branch where Child fails while walking
// the path: deriving a hardened child from a public extended key.
func TestDeriveChildFromPathChildError(t *testing.T) {
	t.Parallel()

	k, err := compat.NewKeyFromString(testXPriv)
	require.NoError(t, err)
	pub, err := k.Neuter()
	require.NoError(t, err)

	_, err = pub.DeriveChildFromPath("0'")
	require.ErrorIs(t, err, compat.ErrDeriveHardFromPublic)
}

// TestDerivePublicKeyFromPathError covers the error branch of DerivePublicKeyFromPath
// when the derivation path itself is invalid.
func TestDerivePublicKeyFromPathError(t *testing.T) {
	t.Parallel()

	k, err := compat.NewKeyFromString(testXPriv)
	require.NoError(t, err)

	_, err = k.DerivePublicKeyFromPath("not-a-valid-path")
	require.Error(t, err)
}
