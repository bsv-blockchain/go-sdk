package transaction

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHDPrivateKeyToPublicKeyID_MainNet(t *testing.T) {
	// MainNet HDPrivateKeyID: {0x04, 0x88, 0xad, 0xe4} -> HDPublicKeyID: {0x04, 0x88, 0xb2, 0x1e}
	privID := MainNet.HDPrivateKeyID[:]
	pubID, err := HDPrivateKeyToPublicKeyID(privID)
	require.NoError(t, err)
	require.Equal(t, MainNet.HDPublicKeyID[:], pubID)
}

func TestHDPrivateKeyToPublicKeyID_TestNet(t *testing.T) {
	// TestNet HDPrivateKeyID: {0x04, 0x35, 0x83, 0x94} -> HDPublicKeyID: {0x04, 0x35, 0x87, 0xcf}
	privID := TestNet.HDPrivateKeyID[:]
	pubID, err := HDPrivateKeyToPublicKeyID(privID)
	require.NoError(t, err)
	require.Equal(t, TestNet.HDPublicKeyID[:], pubID)
}

func TestHDPrivateKeyToPublicKeyID_WrongLength(t *testing.T) {
	// ID must be exactly 4 bytes.
	_, err := HDPrivateKeyToPublicKeyID([]byte{0x01, 0x02, 0x03})
	require.ErrorIs(t, err, ErrUnknownHDKeyID)
}

func TestHDPrivateKeyToPublicKeyID_TooLong(t *testing.T) {
	_, err := HDPrivateKeyToPublicKeyID([]byte{0x01, 0x02, 0x03, 0x04, 0x05})
	require.ErrorIs(t, err, ErrUnknownHDKeyID)
}

func TestHDPrivateKeyToPublicKeyID_Empty(t *testing.T) {
	_, err := HDPrivateKeyToPublicKeyID([]byte{})
	require.ErrorIs(t, err, ErrUnknownHDKeyID)
}

func TestHDPrivateKeyToPublicKeyID_UnknownKey(t *testing.T) {
	// A 4-byte key that is not registered.
	_, err := HDPrivateKeyToPublicKeyID([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	require.ErrorIs(t, err, ErrUnknownHDKeyID)
}

func TestRegister_NewNetwork(t *testing.T) {
	customParams := &Params{
		Name:                   "custom",
		LegacyPubKeyHashAddrID: 0x42,
		LegacyScriptHashAddrID: 0x43,
		PrivateKeyID:           0x44,
		HDPrivateKeyID:         [4]byte{0xDE, 0xAD, 0xBE, 0xEF},
		HDPublicKeyID:          [4]byte{0xCA, 0xFE, 0xBA, 0xBE},
	}

	err := Register(customParams)
	require.NoError(t, err)

	// After registration, the private->public lookup should work.
	pubID, err := HDPrivateKeyToPublicKeyID(customParams.HDPrivateKeyID[:])
	require.NoError(t, err)
	require.Equal(t, customParams.HDPublicKeyID[:], pubID)
}

func TestRegister_ReturnsNilError(t *testing.T) {
	// Register always returns nil; verify that contract holds.
	err := Register(&MainNet)
	require.NoError(t, err)
}

func TestNetworkConstants(t *testing.T) {
	require.Equal(t, "mainnet", NetworkMain)
	require.Equal(t, "regtest", NetworkTest)
}

func TestMainNetParams(t *testing.T) {
	require.Equal(t, "mainnet", MainNet.Name)
	require.Equal(t, byte(0x00), MainNet.LegacyPubKeyHashAddrID)
	require.Equal(t, byte(0x80), MainNet.PrivateKeyID)
	require.Equal(t, [4]byte{0x04, 0x88, 0xad, 0xe4}, MainNet.HDPrivateKeyID)
	require.Equal(t, [4]byte{0x04, 0x88, 0xb2, 0x1e}, MainNet.HDPublicKeyID)
}

func TestTestNetParams(t *testing.T) {
	require.Equal(t, "regtest", TestNet.Name)
	require.Equal(t, byte(0x6f), TestNet.LegacyPubKeyHashAddrID)
	require.Equal(t, byte(0xef), TestNet.PrivateKeyID)
	require.Equal(t, [4]byte{0x04, 0x35, 0x83, 0x94}, TestNet.HDPrivateKeyID)
	require.Equal(t, [4]byte{0x04, 0x35, 0x87, 0xcf}, TestNet.HDPublicKeyID)
}
