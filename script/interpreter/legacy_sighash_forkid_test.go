package interpreter

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/errs"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// P2PKH spend whose signature is SIGHASH_ALL (0x01) and verifies over the
// legacy digest. bitcoin-sv v1.2.2 rejects it with SCRIPT_ERR_MUST_USE_FORKID
// once SCRIPT_ENABLE_SIGHASH_FORKID is set, and accepts it otherwise.
// script_tests.json never pairs a verifying no-FORKID signature with that
// flag, so an in-range legacy hash type can skip the guard and still look
// green (issue #373).
const (
	legacySighashTxHex = "0100000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
		"000000006b483045022100dfef1d8a69c1db59d9577aca3234a811a94af469ee201644072df50e574d04830220" +
		"595165479ab33d0e7840a20393eafb225c8c59d409512648f1edf92a34fcd6a3012102466d7fcae563e5cb09a0" +
		"d1870bb580344804617879a14949cf22285f1bae3f27ffffffff01ac840100000000001976a914531260aa2a19" +
		"9e228c537dfa42c82bea2c7c1f4d88ac00000000"
	legacySighashPrevScriptHex = "76a914531260aa2a199e228c537dfa42c82bea2c7c1f4d88ac"
	legacySighashPrevSatoshis  = 100000
)

func legacySighashSpend(t *testing.T) (*transaction.Transaction, *transaction.TransactionOutput) {
	t.Helper()
	tx, err := transaction.NewTransactionFromHex(legacySighashTxHex)
	require.NoError(t, err)
	lock, err := script.NewFromHex(legacySighashPrevScriptHex)
	require.NoError(t, err)
	return tx, &transaction.TransactionOutput{Satoshis: legacySighashPrevSatoshis, LockingScript: lock}
}

// TestLegacySighashForkID covers both sides of EnableSighashForkID for a
// signature that really does verify. The node's MUST_USE_FORKID is
// errs.ErrMustUseForkID; ErrIllegalForkID is the other direction (the ForkID
// bit set while the flag is off).
func TestLegacySighashForkID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		flags   scriptflag.Flag
		wantErr errs.ErrorCode
	}{
		{
			name:    "accepted under strict encoding without EnableSighashForkID",
			flags:   scriptflag.VerifyStrictEncoding,
			wantErr: errs.ErrOK,
		},
		{
			name:    "accepted after Genesis without EnableSighashForkID",
			flags:   scriptflag.VerifyStrictEncoding | scriptflag.UTXOAfterGenesis,
			wantErr: errs.ErrOK,
		},
		{
			name:    "rejected under strict encoding and EnableSighashForkID",
			flags:   scriptflag.VerifyStrictEncoding | scriptflag.EnableSighashForkID,
			wantErr: errs.ErrMustUseForkID,
		},
		{
			name: "rejected after Chronicle",
			flags: scriptflag.VerifyStrictEncoding | scriptflag.EnableSighashForkID |
				scriptflag.UTXOAfterGenesis | scriptflag.UTXOAfterChronicle,
			wantErr: errs.ErrMustUseForkID,
		},
		{
			name: "rejected under node consensus flags",
			flags: scriptflag.Bip16 | scriptflag.VerifyStrictEncoding | scriptflag.VerifyDERSignatures |
				scriptflag.VerifyLowS | scriptflag.VerifyMinimalData | scriptflag.VerifyNullFail |
				scriptflag.VerifySigPushOnly | scriptflag.EnableSighashForkID |
				scriptflag.UTXOAfterGenesis | scriptflag.UTXOAfterChronicle,
			wantErr: errs.ErrMustUseForkID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tx, prev := legacySighashSpend(t)
			err := NewEngine().Execute(WithTx(tx, 0, prev), WithFlags(tt.flags))
			if tt.wantErr == errs.ErrOK {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.True(t, errs.IsErrorCode(err, tt.wantErr), "got %v", err)
		})
	}
}
