package transaction

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSighashFlag_Has(t *testing.T) {
	tests := []struct {
		name     string
		flag     Flag
		check    Flag
		expected bool
	}{
		{
			name:     "All contains All",
			flag:     All,
			check:    All,
			expected: true,
		},
		{
			name:     "None contains None",
			flag:     None,
			check:    None,
			expected: true,
		},
		{
			name:     "AllForkID contains ForkID",
			flag:     AllForkID,
			check:    ForkID,
			expected: true,
		},
		{
			name:     "AllForkID contains All",
			flag:     AllForkID,
			check:    All,
			expected: true,
		},
		{
			name:     "All does not contain ForkID",
			flag:     All,
			check:    ForkID,
			expected: false,
		},
		{
			name:     "AnyOneCanPayForkID contains AnyOneCanPay",
			flag:     AnyOneCanPayForkID,
			check:    AnyOneCanPay,
			expected: true,
		},
		{
			name:     "AnyOneCanPayForkID contains ForkID",
			flag:     AnyOneCanPayForkID,
			check:    ForkID,
			expected: true,
		},
		{
			// Single=0x3, None=0x2: 0x3 & 0x2 == 0x2, so Has returns true.
			// Has is a pure bitmask subset check, not equality.
			name:     "Single bits include None bits (subset check)",
			flag:     Single,
			check:    None,
			expected: true,
		},
		{
			name:     "Old (zero) contains Old (zero)",
			flag:     Old,
			check:    Old,
			expected: true,
		},
		{
			name:     "All does not contain AnyOneCanPay",
			flag:     All,
			check:    AnyOneCanPay,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.flag.Has(tt.check)
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestSighashFlag_HasWithMask(t *testing.T) {
	tests := []struct {
		name     string
		flag     Flag
		check    Flag
		expected bool
	}{
		{
			name:     "All masked is All",
			flag:     All,
			check:    All,
			expected: true,
		},
		{
			name:     "AllForkID masked is All",
			flag:     AllForkID,
			check:    All,
			expected: true,
		},
		{
			name:     "NoneForkID masked is None",
			flag:     NoneForkID,
			check:    None,
			expected: true,
		},
		{
			name:     "SingleForkID masked is Single",
			flag:     SingleForkID,
			check:    Single,
			expected: true,
		},
		{
			name:     "AllForkID masked is not None",
			flag:     AllForkID,
			check:    None,
			expected: false,
		},
		{
			name:     "AnyOneCanPay masked against All is false",
			flag:     AnyOneCanPay,
			check:    All,
			expected: false,
		},
		{
			name:     "AnyOneCanPay with ForkID masked is ForkID bits only",
			flag:     AnyOneCanPayForkID,
			check:    Flag(0x00),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.flag.HasWithMask(tt.check)
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestSighashFlag_String(t *testing.T) {
	tests := []struct {
		flag     Flag
		expected string
	}{
		{All, "ALL"},
		{None, "NONE"},
		{Single, "SINGLE"},
		{All | AnyOneCanPay, "ALL|ANYONECANPAY"},
		{None | AnyOneCanPay, "NONE|ANYONECANPAY"},
		{Single | AnyOneCanPay, "SINGLE|ANYONECANPAY"},
		{AllForkID, "ALL|FORKID"},
		{NoneForkID, "NONE|FORKID"},
		{SingleForkID, "SINGLE|FORKID"},
		{AllForkID | AnyOneCanPay, "ALL|FORKID|ANYONECANPAY"},
		{NoneForkID | AnyOneCanPay, "NONE|FORKID|ANYONECANPAY"},
		{SingleForkID | AnyOneCanPay, "SINGLE|FORKID|ANYONECANPAY"},
		// Unrecognised flags fall back to "ALL"
		{Flag(0xFF), "ALL"},
		{Old, "ALL"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.flag.String()
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestSighashForkIDComposition(t *testing.T) {
	// Verify the ForkID compound constants are composed correctly.
	require.Equal(t, Flag(0x41), AllForkID)
	require.Equal(t, Flag(0x42), NoneForkID)
	require.Equal(t, Flag(0x43), SingleForkID)
	require.Equal(t, Flag(0xC0), AnyOneCanPayForkID)
}
