package tu

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

// GetByte32FromString returns a [32]byte from a string
func GetByte32FromString(s string) [32]byte {
	if len([]byte(s)) > 32 {
		panic(fmt.Sprintf("string byte length must be less than 32, got %d", len([]byte(s))))
	}
	var b [32]byte
	copy(b[:], s)
	return b
}

// GetByte32FromBase64String returns a [32]byte from a base64 string
func GetByte32FromBase64String(t *testing.T, s string) [32]byte {
	var a [32]byte
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		require.NoError(t, fmt.Errorf("error decoding base64 string: %w", err))
	}
	if len(b) > 32 {
		require.NoError(t, fmt.Errorf("byte length must be less than 32"))
	}
	copy(a[:], b)
	return a
}

// GetByte32FromHexString returns a [32]byte from a hex string
func GetByte32FromHexString(t *testing.T, s string) [32]byte {
	var a [32]byte
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	if len(b) > 32 {
		require.NoError(t, fmt.Errorf("byte length must be less than 32"))
	}
	copy(a[:], b)
	return a
}

func GetPKFromString(s string) *ec.PublicKey {
	return GetPKFromBytes([]byte(s))
}

func GetPKFromBytes(b []byte) *ec.PublicKey {
	pk, _ := ec.PrivateKeyFromBytes(b)
	return pk.PubKey()
}

// GetPKFromHex returns a PublicKey from a hex string
func GetPKFromHex(t *testing.T, s string) *ec.PublicKey {
	pk, err := ec.PublicKeyFromString(s)
	require.NoError(t, err)
	return pk
}

// GetSigFromHex returns a Signature from a hex string
func GetSigFromHex(t *testing.T, s string) *ec.Signature {
	d, err := hex.DecodeString(s)
	require.NoError(t, err, fmt.Sprintf("error decoding hex string '%s': %v", s, err))
	sig, err := ec.ParseSignature(d)
	require.NoError(t, err)
	return sig
}

// GetByteFromHexString returns a []byte from a hex string
func GetByteFromHexString(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func OutpointFromString(t *testing.T, s string) *wallet.Outpoint {
	outpoint, err := wallet.OutpointFromString(s)
	require.NoError(t, err, fmt.Sprintf("error creating wallet.Outpoint from string '%s': %v", s, err))
	return outpoint
}

func HashFromString(t *testing.T, s string) chainhash.Hash {
	hash, err := chainhash.NewHashFromHex(s)
	require.NoError(t, err, fmt.Sprintf("error creating wallet.Outpoint from string '%s': %v", s, err))
	return *hash
}
