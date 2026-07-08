package util

import "encoding/binary"

// ReverseBytes reverses the bytes (little endian/big endian).
// This is used when computing merkle trees in Bitcoin, for example.
func ReverseBytes(a []byte) []byte {
	tmp := make([]byte, len(a))
	copy(tmp, a)

	for i, j := 0, len(a)-1; i < j; i, j = i+1, j-1 {
		tmp[i], tmp[j] = tmp[j], tmp[i]
	}
	return tmp
}

// ReverseBytesInPlace reverses the bytes (little endian/big endian) in place (no extra memory allocation).
func ReverseBytesInPlace(a []byte) {
	for i, j := 0, len(a)-1; i < j; i, j = i+1, j-1 {
		a[i], a[j] = a[j], a[i]
	}
}

// LittleEndianBytes returns a byte array in little endian from an unsigned integer of 32 bytes.
func LittleEndianBytes(v, l uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, v)
	return buf[:l] // Return only the first l bytes
}
