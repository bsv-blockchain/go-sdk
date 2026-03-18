// Copyright (c) 2024 The bsv-blockchain developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package errs

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNewError_NoArgs verifies that NewError without format args creates the
// correct Error value.
func TestNewError_NoArgs(t *testing.T) {
	t.Parallel()

	e := NewError(ErrInternal, "internal error")
	require.Equal(t, ErrInternal, e.ErrorCode)
	require.Equal(t, "internal error", e.Description)
	require.Equal(t, "internal error", e.Error())
}

// TestNewError_WithFormatArgs verifies that NewError interpolates printf-style
// format arguments into the description.
func TestNewError_WithFormatArgs(t *testing.T) {
	t.Parallel()

	e := NewError(ErrInvalidIndex, "index %d out of range for length %d", 5, 3)
	require.Equal(t, ErrInvalidIndex, e.ErrorCode)
	require.Equal(t, "index 5 out of range for length 3", e.Description)
	require.Equal(t, "index 5 out of range for length 3", e.Error())
}

// TestNewError_StringFormatArg verifies string format args work correctly.
func TestNewError_StringFormatArg(t *testing.T) {
	t.Parallel()

	e := NewError(ErrUnsupportedAddress, "unsupported address type: %s", "P2SH")
	require.Equal(t, ErrUnsupportedAddress, e.ErrorCode)
	require.Equal(t, "unsupported address type: P2SH", e.Description)
}

// TestNewError_ErrOK verifies NewError works with ErrOK.
func TestNewError_ErrOK(t *testing.T) {
	t.Parallel()

	e := NewError(ErrOK, "ok")
	require.Equal(t, ErrOK, e.ErrorCode)
	require.Equal(t, "ok", e.Description)
}

// TestNewError_MultipleFormatVerbs verifies multiple format verbs in a single
// description string.
func TestNewError_MultipleFormatVerbs(t *testing.T) {
	t.Parallel()

	e := NewError(ErrScriptTooBig, "script size %d exceeds limit %d by %d bytes", 1100, 1000, 100)
	require.Equal(t, ErrScriptTooBig, e.ErrorCode)
	require.Equal(t, "script size 1100 exceeds limit 1000 by 100 bytes", e.Description)
}

// TestNewError_ImplementsError confirms that the Error returned by NewError
// satisfies the standard error interface.
func TestNewError_ImplementsError(t *testing.T) {
	t.Parallel()

	e := NewError(ErrEvalFalse, "eval false")
	var _ error = e
	require.Equal(t, "eval false", e.Error())
}

// TestIsErrorCode verifies that IsErrorCode correctly identifies errors by
// their code and returns false for non-matching or nil errors.
func TestIsErrorCode(t *testing.T) {
	t.Parallel()

	t.Run("matching error code", func(t *testing.T) {
		err := NewError(ErrInternal, "internal")
		require.True(t, IsErrorCode(err, ErrInternal))
	})

	t.Run("non-matching error code", func(t *testing.T) {
		err := NewError(ErrInternal, "internal")
		require.False(t, IsErrorCode(err, ErrOK))
	})

	t.Run("nil error", func(t *testing.T) {
		require.False(t, IsErrorCode(nil, ErrInternal))
	})

	t.Run("non-Error error type", func(t *testing.T) {
		err := errors.New("plain error")
		require.False(t, IsErrorCode(err, ErrInternal))
	})

	t.Run("ErrOK code matches ErrOK error", func(t *testing.T) {
		err := NewError(ErrOK, "ok")
		require.True(t, IsErrorCode(err, ErrOK))
	})

	t.Run("ErrIllegalForkID code", func(t *testing.T) {
		err := NewError(ErrIllegalForkID, "bad fork id")
		require.True(t, IsErrorCode(err, ErrIllegalForkID))
	})

	t.Run("wrapped Error is still matched", func(t *testing.T) {
		wrapped := fmt.Errorf("wrapped: %w", NewError(ErrVerify, "verify failed"))
		require.True(t, IsErrorCode(wrapped, ErrVerify))
	})

	t.Run("ErrEarlyReturn code", func(t *testing.T) {
		err := NewError(ErrEarlyReturn, "early return")
		require.True(t, IsErrorCode(err, ErrEarlyReturn))
	})

	t.Run("ErrSigHighS code", func(t *testing.T) {
		err := NewError(ErrSigHighS, "sig high s")
		require.True(t, IsErrorCode(err, ErrSigHighS))
	})

	t.Run("ErrNullFail code", func(t *testing.T) {
		err := NewError(ErrNullFail, "null fail")
		require.True(t, IsErrorCode(err, ErrNullFail))
	})

	t.Run("ErrDiscourageUpgradableNOPs code", func(t *testing.T) {
		err := NewError(ErrDiscourageUpgradableNOPs, "upgradable nop")
		require.True(t, IsErrorCode(err, ErrDiscourageUpgradableNOPs))
	})
}

// TestIsErrorCode_CoverageForAllCodes exercises IsErrorCode for every defined
// ErrorCode to ensure the function handles all variants.
func TestIsErrorCode_CoverageForAllCodes(t *testing.T) {
	t.Parallel()

	// Build a slice of (code, Error) pairs using literal-compatible calls.
	type pair struct {
		code ErrorCode
		err  Error
	}
	pairs := []pair{
		{ErrInternal, NewError(ErrInternal, "ErrInternal")},
		{ErrOK, NewError(ErrOK, "ErrOK")},
		{ErrInvalidFlags, NewError(ErrInvalidFlags, "ErrInvalidFlags")},
		{ErrInvalidIndex, NewError(ErrInvalidIndex, "ErrInvalidIndex")},
		{ErrUnsupportedAddress, NewError(ErrUnsupportedAddress, "ErrUnsupportedAddress")},
		{ErrNotMultisigScript, NewError(ErrNotMultisigScript, "ErrNotMultisigScript")},
		{ErrTooManyRequiredSigs, NewError(ErrTooManyRequiredSigs, "ErrTooManyRequiredSigs")},
		{ErrTooMuchNullData, NewError(ErrTooMuchNullData, "ErrTooMuchNullData")},
		{ErrInvalidParams, NewError(ErrInvalidParams, "ErrInvalidParams")},
		{ErrEarlyReturn, NewError(ErrEarlyReturn, "ErrEarlyReturn")},
		{ErrEmptyStack, NewError(ErrEmptyStack, "ErrEmptyStack")},
		{ErrEvalFalse, NewError(ErrEvalFalse, "ErrEvalFalse")},
		{ErrScriptUnfinished, NewError(ErrScriptUnfinished, "ErrScriptUnfinished")},
		{ErrInvalidProgramCounter, NewError(ErrInvalidProgramCounter, "ErrInvalidProgramCounter")},
		{ErrScriptTooBig, NewError(ErrScriptTooBig, "ErrScriptTooBig")},
		{ErrElementTooBig, NewError(ErrElementTooBig, "ErrElementTooBig")},
		{ErrTooManyOperations, NewError(ErrTooManyOperations, "ErrTooManyOperations")},
		{ErrStackOverflow, NewError(ErrStackOverflow, "ErrStackOverflow")},
		{ErrInvalidPubKeyCount, NewError(ErrInvalidPubKeyCount, "ErrInvalidPubKeyCount")},
		{ErrInvalidSignatureCount, NewError(ErrInvalidSignatureCount, "ErrInvalidSignatureCount")},
		{ErrNumberTooBig, NewError(ErrNumberTooBig, "ErrNumberTooBig")},
		{ErrNumberTooSmall, NewError(ErrNumberTooSmall, "ErrNumberTooSmall")},
		{ErrDivideByZero, NewError(ErrDivideByZero, "ErrDivideByZero")},
		{ErrVerify, NewError(ErrVerify, "ErrVerify")},
		{ErrEqualVerify, NewError(ErrEqualVerify, "ErrEqualVerify")},
		{ErrNumEqualVerify, NewError(ErrNumEqualVerify, "ErrNumEqualVerify")},
		{ErrCheckSigVerify, NewError(ErrCheckSigVerify, "ErrCheckSigVerify")},
		{ErrCheckMultiSigVerify, NewError(ErrCheckMultiSigVerify, "ErrCheckMultiSigVerify")},
		{ErrDisabledOpcode, NewError(ErrDisabledOpcode, "ErrDisabledOpcode")},
		{ErrReservedOpcode, NewError(ErrReservedOpcode, "ErrReservedOpcode")},
		{ErrMalformedPush, NewError(ErrMalformedPush, "ErrMalformedPush")},
		{ErrInvalidStackOperation, NewError(ErrInvalidStackOperation, "ErrInvalidStackOperation")},
		{ErrUnbalancedConditional, NewError(ErrUnbalancedConditional, "ErrUnbalancedConditional")},
		{ErrInvalidInputLength, NewError(ErrInvalidInputLength, "ErrInvalidInputLength")},
		{ErrMinimalData, NewError(ErrMinimalData, "ErrMinimalData")},
		{ErrMinimalIf, NewError(ErrMinimalIf, "ErrMinimalIf")},
		{ErrInvalidSigHashType, NewError(ErrInvalidSigHashType, "ErrInvalidSigHashType")},
		{ErrSigTooShort, NewError(ErrSigTooShort, "ErrSigTooShort")},
		{ErrSigTooLong, NewError(ErrSigTooLong, "ErrSigTooLong")},
		{ErrSigInvalidSeqID, NewError(ErrSigInvalidSeqID, "ErrSigInvalidSeqID")},
		{ErrSigInvalidDataLen, NewError(ErrSigInvalidDataLen, "ErrSigInvalidDataLen")},
		{ErrSigMissingSTypeID, NewError(ErrSigMissingSTypeID, "ErrSigMissingSTypeID")},
		{ErrSigMissingSLen, NewError(ErrSigMissingSLen, "ErrSigMissingSLen")},
		{ErrSigInvalidSLen, NewError(ErrSigInvalidSLen, "ErrSigInvalidSLen")},
		{ErrSigInvalidRIntID, NewError(ErrSigInvalidRIntID, "ErrSigInvalidRIntID")},
		{ErrSigZeroRLen, NewError(ErrSigZeroRLen, "ErrSigZeroRLen")},
		{ErrSigNegativeR, NewError(ErrSigNegativeR, "ErrSigNegativeR")},
		{ErrSigTooMuchRPadding, NewError(ErrSigTooMuchRPadding, "ErrSigTooMuchRPadding")},
		{ErrSigInvalidSIntID, NewError(ErrSigInvalidSIntID, "ErrSigInvalidSIntID")},
		{ErrSigZeroSLen, NewError(ErrSigZeroSLen, "ErrSigZeroSLen")},
		{ErrSigNegativeS, NewError(ErrSigNegativeS, "ErrSigNegativeS")},
		{ErrSigTooMuchSPadding, NewError(ErrSigTooMuchSPadding, "ErrSigTooMuchSPadding")},
		{ErrSigHighS, NewError(ErrSigHighS, "ErrSigHighS")},
		{ErrNotPushOnly, NewError(ErrNotPushOnly, "ErrNotPushOnly")},
		{ErrSigNullDummy, NewError(ErrSigNullDummy, "ErrSigNullDummy")},
		{ErrPubKeyType, NewError(ErrPubKeyType, "ErrPubKeyType")},
		{ErrCleanStack, NewError(ErrCleanStack, "ErrCleanStack")},
		{ErrNullFail, NewError(ErrNullFail, "ErrNullFail")},
		{ErrDiscourageUpgradableNOPs, NewError(ErrDiscourageUpgradableNOPs, "ErrDiscourageUpgradableNOPs")},
		{ErrNegativeLockTime, NewError(ErrNegativeLockTime, "ErrNegativeLockTime")},
		{ErrUnsatisfiedLockTime, NewError(ErrUnsatisfiedLockTime, "ErrUnsatisfiedLockTime")},
		{ErrIllegalForkID, NewError(ErrIllegalForkID, "ErrIllegalForkID")},
	}

	for _, p := range pairs {
		p := p
		t.Run(p.code.String(), func(t *testing.T) {
			require.True(t, IsErrorCode(p.err, p.code),
				"IsErrorCode should return true for matching code")
			// Pick a different code that is definitely not the same.
			differentCode := p.code + 1
			if differentCode >= numErrorCodes {
				differentCode = ErrInternal
			}
			require.False(t, IsErrorCode(p.err, differentCode),
				"IsErrorCode should return false for a different code")
		})
	}
}
