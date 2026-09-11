package util_test

import (
	"bytes"
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/util"
)

// readVarIntReference decodes a varint the way Reader.ReadVarInt used to:
// through VarInt.ReadFrom over an io.Reader. It returns the decoded value and
// the number of bytes consumed, or an error on truncated input.
func readVarIntReference(data []byte) (uint64, int, error) {
	var vi util.VarInt
	n, err := vi.ReadFrom(bytes.NewReader(data))
	if err != nil {
		return 0, 0, err
	}
	return uint64(vi), int(n), nil
}

// TestReadVarIntBoundaries pins Reader.ReadVarInt over every width boundary:
// the decoded value must match and Pos must advance by exactly VarInt.Length().
func TestReadVarIntBoundaries(t *testing.T) {
	t.Parallel()

	values := []uint64{
		0, 1, 0xfc, 0xfd, 0xfe, 0xff,
		0x100, 0xffff, 0x10000, 0xffffffff,
		0x100000000, math.MaxUint64 - 1, math.MaxUint64,
	}
	for _, v := range values {
		enc := util.VarInt(v).Bytes()
		r := util.NewReader(enc)
		got, err := r.ReadVarInt()
		require.NoErrorf(t, err, "value %#x", v)
		require.Equalf(t, v, got, "value %#x", v)
		require.Equalf(t, util.VarInt(v).Length(), r.Pos, "value %#x consumed", v)
	}
}

// TestReadVarIntTruncatedErrors ensures every width errors (not panics) when the
// buffer is one byte short, matching the old ReadFrom behavior.
func TestReadVarIntTruncatedErrors(t *testing.T) {
	t.Parallel()

	for _, v := range []uint64{0xffff, 0xffffffff, math.MaxUint64} {
		enc := util.VarInt(v).Bytes()
		r := util.NewReader(enc[:len(enc)-1]) // drop the last byte
		_, err := r.ReadVarInt()
		require.Errorf(t, err, "value %#x truncated", v)
	}

	// Empty buffer also errors.
	_, err := util.NewReader(nil).ReadVarInt()
	require.Error(t, err)
}

// TestReadVarIntMatchesReadFrom is a differential test: for arbitrary bytes,
// Reader.ReadVarInt must agree with the old VarInt.ReadFrom path on the decoded
// value, the number of bytes consumed, and whether it errors.
func TestReadVarIntMatchesReadFrom(t *testing.T) {
	t.Parallel()

	inputs := [][]byte{
		{},
		{0x00},
		{0xfc},
		{0xfd},
		{0xfd, 0x01},
		{0xfd, 0x01, 0x02},
		{0xfe},
		{0xfe, 0x01, 0x02, 0x03, 0x04},
		{0xff},
		{0xff, 1, 2, 3, 4, 5, 6, 7, 8},
		{0xfd, 0xff, 0xff, 0xaa, 0xbb}, // extra trailing bytes must be ignored
	}
	for _, data := range inputs {
		r := util.NewReader(data)
		got, gotErr := r.ReadVarInt()

		refVal, refN, refErr := readVarIntReference(data)

		require.Equalf(t, refErr != nil, gotErr != nil, "error parity for %x", data)
		if refErr == nil {
			require.Equalf(t, refVal, got, "value for %x", data)
			require.Equalf(t, refN, r.Pos, "consumed for %x", data)
		}
	}
}
