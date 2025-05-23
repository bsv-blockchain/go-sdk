package tu

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
