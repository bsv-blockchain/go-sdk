package util_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/stretchr/testify/assert"
)

func convertIntToBytes(int uint64) []byte {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, int); err != nil {
		return nil
	}
	return buf.Bytes()
}

func TestDecodeVarInt(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		testName       string
		input          []byte
		expectedResult uint64
		expectedSize   int
	}{
		{"0xff", convertIntToBytes(0xff), 0, 9},
		{"0xfe", convertIntToBytes(0xfe), 0, 5},
		{"0xfd", convertIntToBytes(0xfd), 0, 3},
		{"1", convertIntToBytes(1), 1, 1},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			r, s := util.NewVarIntFromBytes(test.input)
			assert.Equal(t, test.expectedResult, uint64(r))
			assert.Equal(t, test.expectedSize, s)
		})
	}
}

func TestVarIntUpperLimitInc(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		testName       string
		input          uint64
		expectedResult int
	}{
		{"0", 0, 0},
		{"10", 10, 0},
		{"100", 100, 0},
		{"252", 252, 2},
		{"65535", 65535, 2},
		{"4294967295", 4294967295, 4},
		{"18446744073709551615", 18446744073709551615, -1},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			r := util.VarInt(test.input).UpperLimitInc()
			assert.Equal(t, test.expectedResult, r)
		})
	}
}

func TestVarInt(t *testing.T) {
	t.Parallel()

	var varIntTests = []struct {
		testName    string
		input       uint64
		expectedLen int
	}{
		{"VarInt 1 byte Lower", 0, 1},
		{"VarInt 1 byte Upper", 252, 1},
		{"VarInt 3 byte Lower", 253, 3},
		{"VarInt 3 byte Upper", 65535, 3},
		{"VarInt 5 byte Lower", 65536, 5},
		{"VarInt 5 byte Upper", 4294967295, 5},
		{"VarInt 9 byte Lower", 4294967296, 9},
		{"VarInt 9 byte Upper", 18446744073709551615, 9},
	}

	for _, varIntTest := range varIntTests {
		t.Run(varIntTest.testName, func(t *testing.T) {
			assert.Len(t, util.VarInt(varIntTest.input).Bytes(), varIntTest.expectedLen)
		})
	}
}

func TestVarInt_Size(t *testing.T) {
	tests := map[string]struct {
		v       util.VarInt
		expSize int
	}{
		"252 returns 1": {
			v:       util.VarInt(252),
			expSize: 1,
		},
		"253 returns 3": {
			v:       util.VarInt(253),
			expSize: 3,
		},
		"65535 returns 3": {
			v:       util.VarInt(65535),
			expSize: 3,
		},
		"65536 returns 5": {
			v:       util.VarInt(65536),
			expSize: 5,
		},
		"4294967295 returns 5": {
			v:       util.VarInt(4294967295),
			expSize: 5,
		},
		"4294967296 returns 9": {
			v:       util.VarInt(4294967296),
			expSize: 9,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.expSize, test.v.Length())
		})
	}
}

func TestVarInt_PutBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    uint64
		expected []byte
	}{
		{"1 byte - zero", 0, []byte{0x00}},
		{"1 byte - one", 1, []byte{0x01}},
		{"1 byte - max", 252, []byte{0xfc}},
		{"3 byte - min", 253, []byte{0xfd, 0xfd, 0x00}},
		{"3 byte - max", 65535, []byte{0xfd, 0xff, 0xff}},
		{"5 byte - min", 65536, []byte{0xfe, 0x00, 0x00, 0x01, 0x00}},
		{"5 byte - max", 4294967295, []byte{0xfe, 0xff, 0xff, 0xff, 0xff}},
		{"9 byte - min", 4294967296, []byte{0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}},
		{"9 byte - max", 18446744073709551615, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			v := util.VarInt(test.value)
			buf := make([]byte, v.Length())
			n := v.PutBytes(buf)
			assert.Equal(t, len(test.expected), n)
			assert.Equal(t, test.expected, buf)
			// Verify PutBytes produces same result as Bytes()
			assert.Equal(t, v.Bytes(), buf)
		})
	}
}
