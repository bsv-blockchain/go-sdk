package tu

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

// PadOrTrim returns (size) bytes from input (bb)
// Short bb gets zeros prefixed, Long bb gets left/MSB bits trimmed
func PadOrTrim(bb []byte, size int) []byte {
	l := len(bb)
	if l == size {
		return bb
	}
	if l > size {
		return bb[l-size:]
	}
	tmp := make([]byte, size)
	copy(tmp[size-l:], bb)
	return tmp
}

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

// GetByte33FromString returns a [33]byte from a string
func GetByte33FromString(s string) [33]byte {
	if len([]byte(s)) > 33 {
		panic(fmt.Sprintf("string byte length must be less than 33, got %d", len([]byte(s))))
	}
	var b [33]byte
	copy(b[:], s)
	return b
}

// GetByte33FromHexString returns a [33]byte from a hex string
func GetByte33FromHexString(t *testing.T, s string) [33]byte {
	var a [33]byte
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	if len(b) > 33 {
		require.NoError(t, fmt.Errorf("byte length must be less than 33"))
	}
	copy(a[:], b)
	return a
}

// GetByteFromHexString returns a []byte from a hex string
func GetByteFromHexString(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}
