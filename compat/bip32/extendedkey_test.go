package compat_test

import (
	"testing"

	compat "github.com/bsv-blockchain/go-sdk/compat/bip32"
	chaincfg "github.com/bsv-blockchain/go-sdk/transaction/chaincfg"
	"github.com/stretchr/testify/require"
)

const testXPriv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

func getTestKey(t *testing.T) *compat.ExtendedKey {
	t.Helper()
	k, err := compat.NewKeyFromString(testXPriv)
	require.NoError(t, err)
	return k
}

func TestExtendedKeyIsPrivate(t *testing.T) {
	t.Parallel()

	t.Run("returns true for private key", func(t *testing.T) {
		k := getTestKey(t)
		require.True(t, k.IsPrivate())
	})

	t.Run("returns false for public key", func(t *testing.T) {
		k := getTestKey(t)
		pub, err := k.Neuter()
		require.NoError(t, err)
		require.False(t, pub.IsPrivate())
	})
}

func TestExtendedKeyDepth(t *testing.T) {
	t.Parallel()

	t.Run("root key has depth zero", func(t *testing.T) {
		k := getTestKey(t)
		require.Equal(t, uint8(0), k.Depth())
	})

	t.Run("child key has depth one", func(t *testing.T) {
		k := getTestKey(t)
		child, err := k.Child(0)
		require.NoError(t, err)
		require.Equal(t, uint8(1), child.Depth())
	})
}

func TestExtendedKeyParentFingerprint(t *testing.T) {
	t.Parallel()

	t.Run("root key has zero fingerprint", func(t *testing.T) {
		k := getTestKey(t)
		require.Equal(t, uint32(0), k.ParentFingerprint())
	})

	t.Run("child key has non-zero fingerprint", func(t *testing.T) {
		k := getTestKey(t)
		child, err := k.Child(0)
		require.NoError(t, err)
		require.NotEqual(t, uint32(0), child.ParentFingerprint())
	})
}

func TestExtendedKeyAddress(t *testing.T) {
	t.Parallel()

	t.Run("returns mainnet address for private key", func(t *testing.T) {
		k := getTestKey(t)
		addr := k.Address(&chaincfg.MainNet)
		require.NotEmpty(t, addr)
		// mainnet P2PKH addresses start with '1'
		require.Equal(t, '1', rune(addr[0]))
	})

	t.Run("returns testnet address for public key", func(t *testing.T) {
		k := getTestKey(t)
		pub, err := k.Neuter()
		require.NoError(t, err)
		addr := pub.Address(&chaincfg.TestNet)
		require.NotEmpty(t, addr)
		// testnet P2PKH addresses start with 'm' or 'n'
		require.True(t, addr[0] == 'm' || addr[0] == 'n', "testnet addr should start with m or n, got %s", addr)
	})

	t.Run("returns different address for mainnet vs testnet", func(t *testing.T) {
		k := getTestKey(t)
		mainnetAddr := k.Address(&chaincfg.MainNet)
		testnetAddr := k.Address(&chaincfg.TestNet)
		require.NotEqual(t, mainnetAddr, testnetAddr)
	})
}

func TestExtendedKeyIsForNet(t *testing.T) {
	t.Parallel()

	t.Run("returns true for mainnet key on mainnet", func(t *testing.T) {
		k := getTestKey(t)
		require.True(t, k.IsForNet(&chaincfg.MainNet))
	})

	t.Run("returns false for mainnet key on testnet", func(t *testing.T) {
		k := getTestKey(t)
		require.False(t, k.IsForNet(&chaincfg.TestNet))
	})

	t.Run("returns true after SetNet to testnet", func(t *testing.T) {
		k := getTestKey(t)
		k.SetNet(&chaincfg.TestNet)
		require.True(t, k.IsForNet(&chaincfg.TestNet))
	})

	t.Run("public key is for mainnet", func(t *testing.T) {
		k := getTestKey(t)
		pub, err := k.Neuter()
		require.NoError(t, err)
		require.True(t, pub.IsForNet(&chaincfg.MainNet))
	})
}

func TestExtendedKeySetNet(t *testing.T) {
	t.Parallel()

	t.Run("sets network for private key", func(t *testing.T) {
		k := getTestKey(t)
		require.True(t, k.IsForNet(&chaincfg.MainNet))
		k.SetNet(&chaincfg.TestNet)
		require.True(t, k.IsForNet(&chaincfg.TestNet))
		require.False(t, k.IsForNet(&chaincfg.MainNet))
	})

	t.Run("sets network for public key", func(t *testing.T) {
		k := getTestKey(t)
		pub, err := k.Neuter()
		require.NoError(t, err)
		require.True(t, pub.IsForNet(&chaincfg.MainNet))
		pub.SetNet(&chaincfg.TestNet)
		require.True(t, pub.IsForNet(&chaincfg.TestNet))
	})
}

func TestExtendedKeyZero(t *testing.T) {
	t.Parallel()

	t.Run("zeroed key returns sentinel string", func(t *testing.T) {
		k := getTestKey(t)
		k.Zero()
		require.Equal(t, "zeroed extended key", k.String())
	})

	t.Run("zeroed key is no longer private", func(t *testing.T) {
		k := getTestKey(t)
		k.Zero()
		require.False(t, k.IsPrivate())
	})
}

func TestNewMaster(t *testing.T) {
	t.Parallel()

	t.Run("returns error for seed too short", func(t *testing.T) {
		seed := make([]byte, compat.MinSeedBytes-1)
		_, err := compat.NewMaster(seed, &chaincfg.MainNet)
		require.ErrorIs(t, err, compat.ErrInvalidSeedLen)
	})

	t.Run("returns error for seed too long", func(t *testing.T) {
		seed := make([]byte, compat.MaxSeedBytes+1)
		_, err := compat.NewMaster(seed, &chaincfg.MainNet)
		require.ErrorIs(t, err, compat.ErrInvalidSeedLen)
	})

	t.Run("succeeds with valid seed length", func(t *testing.T) {
		seed := make([]byte, compat.RecommendedSeedLen)
		// Fill with non-zero bytes to avoid ErrUnusableSeed
		for i := range seed {
			seed[i] = byte(i + 1)
		}
		k, err := compat.NewMaster(seed, &chaincfg.MainNet)
		require.NoError(t, err)
		require.NotNil(t, k)
		require.True(t, k.IsPrivate())
	})
}

func TestNewKeyFromStringErrors(t *testing.T) {
	t.Parallel()

	t.Run("returns error for empty string", func(t *testing.T) {
		_, err := compat.NewKeyFromString("")
		require.Error(t, err)
	})

	t.Run("returns error for bad checksum", func(t *testing.T) {
		// Modify a valid key string to break checksum
		_, err := compat.NewKeyFromString("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi" + "BAD")
		require.Error(t, err)
	})

	t.Run("returns error for invalid length key", func(t *testing.T) {
		_, err := compat.NewKeyFromString("xprv9s21ZrQH143K")
		require.Error(t, err)
	})
}

func TestExtendedKeyChildErrors(t *testing.T) {
	t.Parallel()

	t.Run("returns error when deriving hardened key from public key", func(t *testing.T) {
		k := getTestKey(t)
		pub, err := k.Neuter()
		require.NoError(t, err)
		_, err = pub.Child(compat.HardenedKeyStart)
		require.ErrorIs(t, err, compat.ErrDeriveHardFromPublic)
	})
}

func TestGenerateSeed(t *testing.T) {
	t.Parallel()

	t.Run("returns valid seed of requested length", func(t *testing.T) {
		seed, err := compat.GenerateSeed(compat.RecommendedSeedLen)
		require.NoError(t, err)
		require.Len(t, seed, compat.RecommendedSeedLen)
	})

	t.Run("returns error for seed length too short", func(t *testing.T) {
		_, err := compat.GenerateSeed(uint8(compat.MinSeedBytes - 1))
		require.Error(t, err)
	})

	t.Run("returns error for seed length too long", func(t *testing.T) {
		_, err := compat.GenerateSeed(uint8(compat.MaxSeedBytes + 1))
		require.Error(t, err)
	})

	t.Run("two generated seeds differ", func(t *testing.T) {
		seed1, err := compat.GenerateSeed(compat.RecommendedSeedLen)
		require.NoError(t, err)
		seed2, err := compat.GenerateSeed(compat.RecommendedSeedLen)
		require.NoError(t, err)
		require.NotEqual(t, seed1, seed2)
	})
}

func TestGenerateHDKeyFromMnemonic(t *testing.T) {
	t.Parallel()

	t.Run("generates key from mnemonic", func(t *testing.T) {
		mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		k, err := compat.GenerateHDKeyFromMnemonic(mnemonic, "", &chaincfg.MainNet)
		require.NoError(t, err)
		require.NotNil(t, k)
		require.True(t, k.IsPrivate())
	})

	t.Run("different passwords produce different keys", func(t *testing.T) {
		mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		k1, err := compat.GenerateHDKeyFromMnemonic(mnemonic, "", &chaincfg.MainNet)
		require.NoError(t, err)
		k2, err := compat.GenerateHDKeyFromMnemonic(mnemonic, "password", &chaincfg.MainNet)
		require.NoError(t, err)
		require.NotEqual(t, k1.String(), k2.String())
	})
}

func TestGetPrivateKeyByPathPublicKeyError(t *testing.T) {
	t.Parallel()

	t.Run("returns error for public key with hardened path", func(t *testing.T) {
		k := getTestKey(t)
		pub, err := k.Neuter()
		require.NoError(t, err)
		// Use hardened index to trigger error
		_, err = compat.GetPrivateKeyByPath(pub, compat.HardenedKeyStart, 0)
		require.Error(t, err)
	})
}

func TestDeriveChildFromPathEmptyPath(t *testing.T) {
	t.Parallel()

	t.Run("empty path returns same key", func(t *testing.T) {
		k := getTestKey(t)
		child, err := k.DeriveChildFromPath("")
		require.NoError(t, err)
		require.Equal(t, k.String(), child.String())
	})

	t.Run("invalid path character returns error", func(t *testing.T) {
		k := getTestKey(t)
		_, err := k.DeriveChildFromPath("abc/def")
		require.Error(t, err)
	})
}
