package feemodel

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCalculateFee(t *testing.T) {
	tests := []struct {
		name          string
		txSize        int
		satoshisPerKB uint64
		expectedFee   uint64
		description   string
	}{
		{
			name:          "240 bytes at 100 sats/KB",
			txSize:        240,
			satoshisPerKB: 100,
			expectedFee:   24,
			description:   "240/1000 * 100 = 24 - tests the bug where casting happened before multiplication",
		},
		{
			name:          "240 bytes at 1 sat/KB",
			txSize:        240,
			satoshisPerKB: 1,
			expectedFee:   1,
			description:   "Edge case that would pass even with buggy implementation",
		},
		{
			name:          "240 bytes at 10 sats/KB",
			txSize:        240,
			satoshisPerKB: 10,
			expectedFee:   3,
			description:   "240/1000 * 10 = 2.4, ceil = 3",
		},
		{
			name:          "250 bytes at 500 sats/KB",
			txSize:        250,
			satoshisPerKB: 500,
			expectedFee:   125,
			description:   "250/1000 * 500 = 125",
		},
		{
			name:          "1000 bytes at 100 sats/KB",
			txSize:        1000,
			satoshisPerKB: 100,
			expectedFee:   100,
			description:   "1000/1000 * 100 = 100",
		},
		{
			name:          "1500 bytes at 100 sats/KB",
			txSize:        1500,
			satoshisPerKB: 100,
			expectedFee:   150,
			description:   "1500/1000 * 100 = 150",
		},
		{
			name:          "1500 bytes at 500 sats/KB",
			txSize:        1500,
			satoshisPerKB: 500,
			expectedFee:   750,
			description:   "1500/1000 * 500 = 750",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fee := calculateFee(tt.txSize, tt.satoshisPerKB)
			require.Equal(t, tt.expectedFee, fee, tt.description)
		})
	}
}
