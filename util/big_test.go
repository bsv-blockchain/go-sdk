package util_test

import (
	"math/big"
	"testing"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUmod(t *testing.T) {
	testCases := []struct {
		name     string
		x        *big.Int
		y        *big.Int
		expected *big.Int
	}{
		{"Positive x, Positive y", big.NewInt(17), big.NewInt(5), big.NewInt(2)},
		{"Negative x, Positive y", big.NewInt(-178), big.NewInt(10), big.NewInt(2)},
		{"Positive x, Negative y", big.NewInt(17), big.NewInt(-5), big.NewInt(2)},
		{"Negative x, Negative y", big.NewInt(-17), big.NewInt(-5), big.NewInt(3)},
		{"Zero x, Positive y", big.NewInt(0), big.NewInt(5), big.NewInt(0)},
		{
			"Large x, Large y",
			new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil),
			new(big.Int).Exp(big.NewInt(2), big.NewInt(255), nil),
			big.NewInt(0),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := util.Umod(tc.x, tc.y)
			if tc.name == "Large x, Large y" {
				t.Logf("Large x, Large y case:")
				t.Logf("x: %s", tc.x.String())
				t.Logf("y: %s", tc.y.String())
				t.Logf("result: %s", result.String())
				t.Logf("expected: %s", tc.expected.String())
			}
			assert.Equal(t, 0, tc.expected.Cmp(result), "Umod(%v, %v) should be %v, got %v", tc.x, tc.y, tc.expected, result)
		})
	}
}

func TestUmodPanic(t *testing.T) {
	assert.Panics(t, func() {
		util.Umod(big.NewInt(10), big.NewInt(0))
	}, "Umod should panic when y is zero")
}

func TestNewRandomBigInt(t *testing.T) {
	testCases := []struct {
		name    string
		byteLen int
	}{
		{"32 bytes", 32},
		{"64 bytes", 64},
		{"128 bytes", 128},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			b := util.NewRandomBigInt(tc.byteLen)
			require.NotNil(t, b)
			require.LessOrEqual(t, len(b.Bytes()), tc.byteLen)
			require.Positive(t, b.BitLen())
		})
	}
}

func TestNewRandomBigIntUniqueness(t *testing.T) {
	b1 := util.NewRandomBigInt(32)
	b2 := util.NewRandomBigInt(32)
	assert.NotEqual(t, b1, b2, "Two random big ints should not be equal")
}
