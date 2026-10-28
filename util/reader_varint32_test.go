package util_test

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/util"
)

// A varint that stands for a 32-bit wire field must be refused when it does not fit,
// not narrowed: 4294967296 would otherwise read as 0 and 4294967297 as 1.
func TestReadVarInt32Bounds(t *testing.T) {
	accepted := []uint64{0, 1, 252, 253, 65535, 65536, math.MaxUint32 - 1, math.MaxUint32}
	for _, v := range accepted {
		got, err := util.NewReader(util.VarInt(v).Bytes()).ReadVarInt32()
		require.NoError(t, err, "value %d", v)
		require.Equal(t, uint32(v), got) //nolint:gosec // v is within uint32 here
	}

	refused := []uint64{math.MaxUint32 + 1, math.MaxUint32 + 2, 1 << 40, math.MaxUint64}
	for _, v := range refused {
		got, err := util.NewReader(util.VarInt(v).Bytes()).ReadVarInt32()
		require.Error(t, err, "value %d must be refused", v)
		require.Contains(t, err.Error(), "0 to 4294967295")
		require.Zero(t, got)
	}
}

func TestReaderHoldErrorReadVarInt32Bounds(t *testing.T) {
	r := util.NewReaderHoldError(util.VarInt(uint64(math.MaxUint32) + 1).Bytes())
	require.Zero(t, r.ReadVarInt32())
	require.Error(t, r.Err)
}
