package compat_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	base58 "github.com/bsv-blockchain/go-sdk/compat/base58"
	compat "github.com/bsv-blockchain/go-sdk/compat/bip32"
	hash "github.com/bsv-blockchain/go-sdk/primitives/hash"
	chaincfg "github.com/bsv-blockchain/go-sdk/transaction/chaincfg"
)

// buildSerializedExtendedKey hand-builds a base58-encoded extended key with a valid
// checksum from the given version and 33-byte key data, so NewKeyFromString error
// branches past the length/checksum checks can be exercised.
func buildSerializedExtendedKey(t *testing.T, version, keyData []byte) string {
	t.Helper()
	require.Len(t, keyData, 33)

	payload := make([]byte, 0, 78)
	payload = append(payload, version...)             // 4 bytes version
	payload = append(payload, 0x00)                   // 1 byte depth
	payload = append(payload, 0x00, 0x00, 0x00, 0x00) // 4 bytes parent fingerprint
	payload = append(payload, 0x00, 0x00, 0x00, 0x00) // 4 bytes child number
	payload = append(payload, make([]byte, 32)...)    // 32 bytes chain code
	payload = append(payload, keyData...)             // 33 bytes key data

	checkSum := hash.Sha256d(payload)[:4]
	payload = append(payload, checkSum...)
	return base58.Encode(payload)
}

// TestChildBeyondMaxDepth covers the max-depth guard in Child.
func TestChildBeyondMaxDepth(t *testing.T) {
	t.Parallel()

	version := chaincfg.MainNet.HDPrivateKeyID[:]
	k := compat.NewExtendedKey(version, make([]byte, 32), make([]byte, 32), []byte{0, 0, 0, 0}, 255, 0, true)

	_, err := k.Child(0)
	require.ErrorIs(t, err, compat.ErrDeriveBeyondMaxDepth)
}

// TestChildPublicNonHardened covers deriving a non-hardened child from a public
// extended key (the point-addition branch of Child).
func TestChildPublicNonHardened(t *testing.T) {
	t.Parallel()

	k, err := compat.NewKeyFromString(testXPriv)
	require.NoError(t, err)
	pub, err := k.Neuter()
	require.NoError(t, err)

	child, err := pub.Child(0)
	require.NoError(t, err)
	require.NotNil(t, child)
	require.False(t, child.IsPrivate())
}

// TestNeuterInvalidVersion covers the branch where Neuter fails to map an unknown
// private version to its public counterpart.
func TestNeuterInvalidVersion(t *testing.T) {
	t.Parallel()

	k := compat.NewExtendedKey([]byte{0x01, 0x02, 0x03, 0x04}, make([]byte, 32), make([]byte, 32), []byte{0, 0, 0, 0}, 0, 0, true)
	_, err := k.Neuter()
	require.Error(t, err)
}

// TestStringPaddedKey covers the leading-zero padding branch of paddedAppend when a
// private key is shorter than 32 bytes.
func TestStringPaddedKey(t *testing.T) {
	t.Parallel()

	version := chaincfg.MainNet.HDPrivateKeyID[:]
	shortKey := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	k := compat.NewExtendedKey(version, shortKey, make([]byte, 32), []byte{0, 0, 0, 0}, 0, 0, true)

	s := k.String()
	require.NotEmpty(t, s)
	require.NotEqual(t, "zeroed extended key", s)
}

// TestNewKeyFromStringBadChecksum covers the checksum-mismatch branch of NewKeyFromString
// while keeping the serialized length valid.
func TestNewKeyFromStringBadChecksum(t *testing.T) {
	t.Parallel()

	decoded, err := base58.Decode(testXPriv)
	require.NoError(t, err)
	// Corrupt the final checksum byte without changing the length.
	decoded[len(decoded)-1] ^= 0xff
	_, err = compat.NewKeyFromString(base58.Encode(decoded))
	require.ErrorIs(t, err, compat.ErrBadChecksum)
}

// TestNewKeyFromStringUnusablePrivateKey covers the branch where the serialized private
// key data is out of range (all zeros).
func TestNewKeyFromStringUnusablePrivateKey(t *testing.T) {
	t.Parallel()

	keyData := make([]byte, 33) // leading 0x00 marks private, remaining 32 bytes all zero
	encoded := buildSerializedExtendedKey(t, chaincfg.MainNet.HDPrivateKeyID[:], keyData)
	_, err := compat.NewKeyFromString(encoded)
	require.ErrorIs(t, err, compat.ErrUnusableSeed)
}

// TestNewKeyFromStringInvalidPublicKey covers the branch where the serialized public key
// data does not parse as a valid point.
func TestNewKeyFromStringInvalidPublicKey(t *testing.T) {
	t.Parallel()

	keyData := make([]byte, 33)
	keyData[0] = 0x01 // invalid pubkey format byte (and not the 0x00 private marker)
	for i := 1; i < 33; i++ {
		keyData[i] = 0xff
	}
	encoded := buildSerializedExtendedKey(t, chaincfg.MainNet.HDPublicKeyID[:], keyData)
	_, err := compat.NewKeyFromString(encoded)
	require.Error(t, err)
}
