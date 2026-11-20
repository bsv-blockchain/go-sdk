package compat_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	compat "github.com/bsv-blockchain/go-sdk/compat/bip32"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	chaincfg "github.com/bsv-blockchain/go-sdk/transaction/chaincfg"
)

// legacyNode models the derivation of releases before the leading-zero fix, from
// the description of the bug alone: a derived private key is kept as the minimal
// big-endian bytes of its value, and a hardened child is computed from those
// bytes left-aligned in the 32-byte ser256 slot.
type legacyNode struct {
	raw   []byte // the key as the old code held it in memory
	chain []byte
}

func legacyMaster(seed []byte) legacyNode {
	h := hmac.New(sha512.New, []byte("Bitcoin seed"))
	h.Write(seed)
	i := h.Sum(nil)
	return legacyNode{raw: i[:32], chain: i[32:]}
}

func (n legacyNode) child(index uint32) legacyNode {
	data := make([]byte, 37)
	if index >= compat.HardenedKeyStart {
		copy(data[1:], n.raw)
	} else {
		x, y := ec.S256().ScalarBaseMult(n.raw)
		pub := ec.PublicKey{Curve: ec.S256(), X: x, Y: y}
		copy(data, pub.Compressed())
	}
	binary.BigEndian.PutUint32(data[33:], index)
	h := hmac.New(sha512.New, n.chain)
	h.Write(data)
	i := h.Sum(nil)
	k := new(big.Int).SetBytes(i[:32])
	k.Add(k, new(big.Int).SetBytes(n.raw)).Mod(k, ec.S256().N)
	return legacyNode{raw: k.Bytes(), chain: i[32:]}
}

func (n legacyNode) key32() []byte {
	return new(big.Int).SetBytes(n.raw).FillBytes(make([]byte, 32))
}

// BIP32 test vector 4, m/0H/1H: Child gives the BIP32 key; ChildNonStandard gives
// the key that earlier releases derived for the same path, which is not BIP32's.
func TestChildNonStandardVector4(t *testing.T) {
	seed, err := hex.DecodeString("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678")
	require.NoError(t, err)
	m, err := compat.NewMaster(seed, &chaincfg.MainNet)
	require.NoError(t, err)

	path := []uint32{compat.HardenedKeyStart + 0, compat.HardenedKeyStart + 1}
	std, legacy := m, m
	for _, i := range path {
		std, err = std.Child(i)
		require.NoError(t, err)
		legacy, err = legacy.ChildNonStandard(i)
		require.NoError(t, err)
	}
	require.Equal(t,
		"xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
		std.String())
	require.Equal(t, "xprv9xJocDuwtYCMMMWTXzA3hDFhGurb5zS5Bc2vRWiwhKJrqEWNkF6J7wnMLW1ajN49fcVCAbepDkkSjyvj9wabYrTGMHLytfotXjFwmjHWXCJ", legacy.String())

	// m/0H has a leading zero byte in test vector 4. Child keeps it in 32 bytes, so
	// its hardened children are the same under both methods and the key is not
	// flagged; ChildNonStandard holds it in 31 bytes, where they differ.
	a, err := m.Child(path[0])
	require.NoError(t, err)
	aPriv, err := a.ECPrivKey()
	require.NoError(t, err)
	require.Zero(t, aPriv.Serialize()[0], "m/0H has a leading zero byte in test vector 4")
	require.False(t, a.HasLeadingZeroKey())
	aLegacy, err := m.ChildNonStandard(path[0])
	require.NoError(t, err)
	require.True(t, aLegacy.HasLeadingZeroKey())
	require.False(t, m.HasLeadingZeroKey())
	h, err := a.Child(path[1])
	require.NoError(t, err)
	hSame, err := a.ChildNonStandard(path[1])
	require.NoError(t, err)
	require.Equal(t, h.String(), hSame.String(), "from the 32-byte key both methods agree")
	hLegacy, err := aLegacy.ChildNonStandard(path[1])
	require.NoError(t, err)
	require.Equal(t, legacy.String(), hLegacy.String())

	affected, err := m.IsPathAffectedByLeadingZero(path...)
	require.NoError(t, err)
	require.True(t, affected)
	affected, err = m.IsPathAffectedByLeadingZero(path[0])
	require.NoError(t, err)
	require.False(t, affected, "the step into a leading-zero key is the same; the next hardened step differs")
}

// ChildNonStandard must equal the earlier releases' derivation on mixed
// hardened and normal paths, and IsPathAffectedByLeadingZero must be true exactly
// when that derivation differs from the specification-only BIP32 reference.
func TestChildNonStandardMatchesEarlierDerivation(t *testing.T) {
	affectedPaths, unaffectedPaths, flagged := 0, 0, 0
	for n := 0; n < 120; n++ {
		seed := sha256.Sum256([]byte{byte(n), byte(n >> 8), 0x42})
		m, err := compat.NewMaster(seed[:], &chaincfg.MainNet)
		require.NoError(t, err)
		old := legacyMaster(seed[:])
		legacy := m

		var path []uint32
		for step := 0; step < 6; step++ {
			index := uint32((n*7+step*3)%4) + uint32(step%2)*compat.HardenedKeyStart
			path = append(path, index)
			legacy, err = legacy.ChildNonStandard(index)
			require.NoError(t, err)
			old = old.child(index)

			priv, perr := legacy.ECPrivKey()
			require.NoError(t, perr)
			require.Equal(t, old.key32(), priv.Serialize(), "seed %d step %d", n, step)

			// HasLeadingZeroKey is true exactly when the next hardened step differs
			// between the two methods.
			hStd, herr := legacy.Child(compat.HardenedKeyStart + 9)
			require.NoError(t, herr)
			hLeg, herr := legacy.ChildNonStandard(compat.HardenedKeyStart + 9)
			require.NoError(t, herr)
			require.Equal(t, legacy.HasLeadingZeroKey(), hStd.String() != hLeg.String(), "seed %d step %d", n, step)
			if legacy.HasLeadingZeroKey() {
				flagged++
			}
		}
		// The BIP32 derivation along the same path (hardened steps only differ when the
		// parent has a leading zero; normal steps use the public key).
		std := m
		for _, index := range path {
			std, err = std.Child(index)
			require.NoError(t, err)
		}
		differs := std.String() != legacy.String()
		got, err := m.IsPathAffectedByLeadingZero(path...)
		require.NoError(t, err)
		require.Equal(t, differs, got, "seed %d", n)
		if differs {
			affectedPaths++
		} else {
			unaffectedPaths++
		}
	}
	require.Positive(t, affectedPaths, "no affected path was exercised")
	require.Positive(t, unaffectedPaths, "no unaffected path was exercised")
	require.Positive(t, flagged, "no key held without its leading zero byte was exercised")
}

// NewExtendedKey does no validation, so a private key can arrive shorter than 32
// bytes. Its hardened children must still use the right-aligned ser256 form.
func TestChildHardenedFromShortKeyIsRightAligned(t *testing.T) {
	full := make([]byte, 32)
	for i := 1; i < 32; i++ {
		full[i] = byte(i * 5)
	}
	short := full[1:] // 31 bytes: the same number without its leading zero byte
	chain := make([]byte, 32)
	for i := range chain {
		chain[i] = byte(0xa0 + i)
	}
	version := chaincfg.MainNet.HDPrivateKeyID[:]

	fromFull := compat.NewExtendedKey(version, full, chain, []byte{0, 0, 0, 0}, 0, 0, true)
	fromShort := compat.NewExtendedKey(version, short, chain, []byte{0, 0, 0, 0}, 0, 0, true)

	a, err := fromFull.Child(compat.HardenedKeyStart + 3)
	require.NoError(t, err)
	b, err := fromShort.Child(compat.HardenedKeyStart + 3)
	require.NoError(t, err)
	require.Equal(t, a.String(), b.String())

	// The earlier left-aligned behaviour differs, so the check is not vacuous.
	c, err := fromShort.ChildNonStandard(compat.HardenedKeyStart + 3)
	require.NoError(t, err)
	require.NotEqual(t, a.String(), c.String())
	require.True(t, fromShort.HasLeadingZeroKey())
	require.False(t, fromFull.HasLeadingZeroKey(), "a 32-byte key with a zero first byte is not flagged")
}

// The string-path forms follow the same rule as stepping with Child and
// ChildNonStandard, using test vector 4.
func TestDeriveChildFromPathNonStandard(t *testing.T) {
	seed, err := hex.DecodeString("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678")
	require.NoError(t, err)
	m, err := compat.NewMaster(seed, &chaincfg.MainNet)
	require.NoError(t, err)

	std, err := m.DeriveChildFromPath("0'/1'")
	require.NoError(t, err)
	require.Equal(t, "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1", std.String())
	legacy, err := m.DeriveChildFromPathNonStandard("0'/1'")
	require.NoError(t, err)
	require.Equal(t, "xprv9xJocDuwtYCMMMWTXzA3hDFhGurb5zS5Bc2vRWiwhKJrqEWNkF6J7wnMLW1ajN49fcVCAbepDkkSjyvj9wabYrTGMHLytfotXjFwmjHWXCJ", legacy.String())

	same, err := m.DeriveChildFromPathNonStandard("")
	require.NoError(t, err)
	require.Equal(t, m.String(), same.String())
	_, err = m.DeriveChildFromPathNonStandard("0'/x")
	require.Error(t, err)
}
