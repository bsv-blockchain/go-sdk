package primitives

// r is a constant used in the multiplication, specific to AES's GF(2^128) field.
var r = []byte{0xe1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// Ghash performs GHASH on the provided input using the provided key
func Ghash(input, hashSubKey []byte) []byte {
	result := make([]byte, 16)

	for i := 0; i < len(input); i += 16 {
		block := input[i:min(i+16, len(input))]
		result = multiply(exclusiveOR(result, block), hashSubKey)
	}

	return result
}

func exclusiveOR(blockA, blockB []byte) []byte {
	result := make([]byte, len(blockA))
	for i := range blockA {
		result[i] = blockA[i] ^ blockB[i]
	}
	return result
}

func rightShift(block []byte) []byte {
	carry := byte(0)
	for i := 0; i < len(block); i++ {
		oldCarry := carry
		carry = block[i] & 0x01
		block[i] >>= 1
		if oldCarry != 0 {
			block[i] |= 0x80
		}
	}
	return block
}

func checkBit(block []byte, index, bit int) bool {
	return (block[index]>>bit)&1 == 1
}

func multiply(block0, block1 []byte) []byte {
	v := make([]byte, len(block1))
	copy(v, block1)
	z := make([]byte, 16)

	for i := 0; i < 16; i++ {
		for j := 7; j >= 0; j-- {
			if checkBit(block0, i, j) {
				z = exclusiveOR(z, v)
			}
			if checkBit(v, 15, 0) {
				v = exclusiveOR(rightShift(v), r)
			} else {
				v = rightShift(v)
			}
		}
	}
	return z
}
