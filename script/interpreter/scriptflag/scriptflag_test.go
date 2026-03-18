package scriptflag

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHasFlag(t *testing.T) {
	tests := []struct {
		name     string
		flags    Flag
		check    Flag
		expected bool
	}{
		{
			name:     "single flag set and checked",
			flags:    Bip16,
			check:    Bip16,
			expected: true,
		},
		{
			name:     "flag not set",
			flags:    Bip16,
			check:    StrictMultiSig,
			expected: false,
		},
		{
			name:     "multiple flags set, check one",
			flags:    Bip16 | StrictMultiSig | VerifyDERSignatures,
			check:    StrictMultiSig,
			expected: true,
		},
		{
			name:     "multiple flags set, check absent flag",
			flags:    Bip16 | StrictMultiSig,
			check:    VerifyLowS,
			expected: false,
		},
		{
			name:     "zero flags, check any flag",
			flags:    0,
			check:    Bip16,
			expected: false,
		},
		{
			name:     "zero flags, check zero",
			flags:    0,
			check:    0,
			expected: true,
		},
		{
			name:     "UTXOAfterGenesis flag",
			flags:    UTXOAfterGenesis,
			check:    UTXOAfterGenesis,
			expected: true,
		},
		{
			name:     "EnableSighashForkID flag",
			flags:    EnableSighashForkID | Bip16,
			check:    EnableSighashForkID,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.flags.HasFlag(tt.check)
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestHasAny(t *testing.T) {
	tests := []struct {
		name     string
		flags    Flag
		check    []Flag
		expected bool
	}{
		{
			name:     "single match",
			flags:    Bip16,
			check:    []Flag{Bip16},
			expected: true,
		},
		{
			name:     "no match",
			flags:    Bip16,
			check:    []Flag{StrictMultiSig, VerifyLowS},
			expected: false,
		},
		{
			name:     "one of many matches",
			flags:    VerifyLowS,
			check:    []Flag{Bip16, StrictMultiSig, VerifyLowS},
			expected: true,
		},
		{
			name:     "empty check list",
			flags:    Bip16,
			check:    []Flag{},
			expected: false,
		},
		{
			name:     "zero flags with no check flags",
			flags:    0,
			check:    []Flag{Bip16},
			expected: false,
		},
		{
			name:     "multiple flags set, first check matches",
			flags:    Bip16 | StrictMultiSig,
			check:    []Flag{Bip16, VerifyLowS},
			expected: true,
		},
		{
			name:     "UTXOAfterGenesis present in multi-check",
			flags:    UTXOAfterGenesis | VerifyMinimalIf,
			check:    []Flag{Bip16, UTXOAfterGenesis},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.flags.HasAny(tt.check...)
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestAddFlag(t *testing.T) {
	tests := []struct {
		name     string
		initial  Flag
		add      Flag
		expected Flag
	}{
		{
			name:     "add to zero",
			initial:  0,
			add:      Bip16,
			expected: Bip16,
		},
		{
			name:     "add second flag",
			initial:  Bip16,
			add:      StrictMultiSig,
			expected: Bip16 | StrictMultiSig,
		},
		{
			name:     "add already-present flag is idempotent",
			initial:  Bip16,
			add:      Bip16,
			expected: Bip16,
		},
		{
			name:     "add multiple flags sequentially",
			initial:  0,
			add:      VerifyDERSignatures,
			expected: VerifyDERSignatures,
		},
		{
			name:     "add UTXOAfterGenesis",
			initial:  Bip16 | StrictMultiSig,
			add:      UTXOAfterGenesis,
			expected: Bip16 | StrictMultiSig | UTXOAfterGenesis,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.initial
			f.AddFlag(tt.add)
			require.Equal(t, tt.expected, f)
		})
	}
}

func TestAddFlagChaining(t *testing.T) {
	var f Flag
	f.AddFlag(Bip16)
	f.AddFlag(StrictMultiSig)
	f.AddFlag(VerifyCleanStack)

	require.True(t, f.HasFlag(Bip16))
	require.True(t, f.HasFlag(StrictMultiSig))
	require.True(t, f.HasFlag(VerifyCleanStack))
	require.False(t, f.HasFlag(VerifyLowS))
	require.True(t, f.HasAny(VerifyLowS, Bip16))
}

func TestAllFlagConstants(t *testing.T) {
	// Verify all flag constants are distinct powers of two (bitmask integrity).
	allFlags := []Flag{
		Bip16,
		StrictMultiSig,
		DiscourageUpgradableNops,
		VerifyCheckLockTimeVerify,
		VerifyCheckSequenceVerify,
		VerifyCleanStack,
		VerifyDERSignatures,
		VerifyLowS,
		VerifyMinimalData,
		VerifyNullFail,
		VerifySigPushOnly,
		EnableSighashForkID,
		VerifyStrictEncoding,
		VerifyBip143SigHash,
		UTXOAfterGenesis,
		VerifyMinimalIf,
	}

	seen := make(map[Flag]bool)
	for _, f := range allFlags {
		require.False(t, seen[f], "duplicate flag value: %d", f)
		seen[f] = true
		// Each constant should be a power of two.
		require.NotZero(t, f)
		require.Zero(t, f&(f-1), "flag %d is not a power of two", f)
	}
}
