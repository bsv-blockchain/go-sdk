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

// refNode is a minimal BIP32 private node used as an independent reference:
// it follows the specification text only (ser256 is always 32 bytes) and shares
// no code with the package under test.
type refNode struct {
	key   *big.Int
	chain []byte
}

func refMaster(seed []byte) refNode {
	h := hmac.New(sha512.New, []byte("Bitcoin seed"))
	h.Write(seed)
	i := h.Sum(nil)
	return refNode{key: new(big.Int).SetBytes(i[:32]), chain: i[32:]}
}

// refHardened derives the hardened child 0x00 || ser256(k) || ser32(index).
func (n refNode) refHardened(index uint32) refNode {
	data := make([]byte, 37)
	n.key.FillBytes(data[1:33])
	binary.BigEndian.PutUint32(data[33:], index)
	h := hmac.New(sha512.New, n.chain)
	h.Write(data)
	i := h.Sum(nil)
	child := new(big.Int).SetBytes(i[:32])
	child.Add(child, n.key).Mod(child, ec.S256().N)
	return refNode{key: child, chain: i[32:]}
}

// BIP32 test vector 4 (a derived private key with a leading zero byte):
// m/0H/1H is the step go-sdk used to get wrong.
func TestChildHardenedFromParentWithLeadingZeroVector4(t *testing.T) {
	seed, err := hex.DecodeString("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678")
	require.NoError(t, err)

	m, err := compat.NewMaster(seed, &chaincfg.MainNet)
	require.NoError(t, err)
	a, err := m.Child(compat.HardenedKeyStart + 0)
	require.NoError(t, err)
	b, err := a.Child(compat.HardenedKeyStart + 1)
	require.NoError(t, err)

	require.Equal(t,
		"xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
		b.String())
}

// Every hardened step must match the specification-only reference, including the
// steps whose parent key has a leading zero byte (about one in 256). The seeds are
// fixed, so the run is deterministic; the guard proves the case was exercised.
func TestChildHardenedMatchesReferenceAcrossLeadingZeroParents(t *testing.T) {
	leadingZeroParents := 0
	for n := 0; n < 600; n++ {
		seed := sha256.Sum256([]byte{byte(n), byte(n >> 8)})
		key, err := compat.NewMaster(seed[:], &chaincfg.MainNet)
		require.NoError(t, err)
		ref := refMaster(seed[:])

		for depth := uint32(0); depth < 6; depth++ {
			for idx := uint32(0); idx < 8; idx++ {
				child, err := key.Child(compat.HardenedKeyStart + idx)
				require.NoError(t, err)
				want := ref.refHardened(compat.HardenedKeyStart + idx)
				priv, err := child.ECPrivKey()
				require.NoError(t, err)
				require.Equal(t, want.key.FillBytes(make([]byte, 32)), priv.Serialize(),
					"seed %d depth %d index %d", n, depth, idx)
			}
			if ref.key.FillBytes(make([]byte, 32))[0] == 0 {
				leadingZeroParents++
			}
			var err error
			key, err = key.Child(compat.HardenedKeyStart + depth)
			require.NoError(t, err)
			ref = ref.refHardened(compat.HardenedKeyStart + depth)
		}
	}
	require.Positive(t, leadingZeroParents, "no parent key with a leading zero byte was exercised")
}
