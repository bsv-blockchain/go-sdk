package tu

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
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

// GetByte32FromString returns a [32]byte from a hex string
func GetByte32FromString(s string) [32]byte {
	if len([]byte(s)) > 32 {
		panic(fmt.Sprintf("string byte length must be less than 32, got %d", len([]byte(s))))
	}
	var b [32]byte
	copy(b[:], s)
	return b
}

// GetByte32FromBase64String returns a [32]byte from a base64 string
func GetByte32FromBase64String(s string) ([32]byte, error) {
	var a [32]byte
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return a, err
	}
	if len(b) > 32 {
		return a, fmt.Errorf("byte length must be less than 32")
	}
	copy(a[:], b)
	return a, nil
}

// GetByte33FromString returns a [33]byte from a hex string
func GetByte33FromString(s string) [33]byte {
	if len([]byte(s)) > 33 {
		panic(fmt.Sprintf("string byte length must be less than 33, got %d", len([]byte(s))))
	}
	var b [33]byte
	copy(b[:], s)
	return b
}

// GetByte33FromHexString returns a [32]byte from a base64 string
func GetByte33FromHexString(s string) ([33]byte, error) {
	var a [33]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return a, err
	}
	if len(b) > 33 {
		return a, fmt.Errorf("byte length must be less than 33")
	}
	copy(a[:], b)
	return a, nil
}
