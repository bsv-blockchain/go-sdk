//go:build cgo && !ios && !android && (darwin || linux) && (amd64 || arm64)

package bdk_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/errs"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/bdk"
)

// nodeVectorsFile is the interpreter's GHSA-rh54-8fpg-8wwf node vector
// corpus; see script/interpreter/node_vectors_test.go.
const nodeVectorsFile = "../../script/interpreter/testdata/node_vectors.json"

type nodeVector struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Heavy       bool     `json:"heavy"`
	Tx          string   `json:"tx"`
	Locks       []string `json:"locks"`
	Sats        []uint64 `json:"sats"`
	CoinHeights []int32  `json:"coinHeights"`
	Spend       int32    `json:"spend"`
	Results     []struct {
		Word      string `json:"word"`
		Consensus bool   `json:"consensus"`
		Valid     bool   `json:"valid"`
	} `json:"results"`
}

// nodeWordFlags maps bitcoin-sv's script-verify flag bits
// (script/script_flags.h) to the SDK's flags.
var nodeWordFlags = map[uint32]scriptflag.Flag{
	1 << 0:  scriptflag.Bip16,
	1 << 1:  scriptflag.VerifyStrictEncoding,
	1 << 2:  scriptflag.VerifyDERSignatures,
	1 << 3:  scriptflag.VerifyLowS,
	1 << 4:  scriptflag.StrictMultiSig,
	1 << 5:  scriptflag.VerifySigPushOnly,
	1 << 6:  scriptflag.VerifyMinimalData,
	1 << 7:  scriptflag.DiscourageUpgradableNops,
	1 << 8:  scriptflag.VerifyCleanStack,
	1 << 9:  scriptflag.VerifyCheckLockTimeVerify,
	1 << 10: scriptflag.VerifyCheckSequenceVerify,
	1 << 13: scriptflag.VerifyMinimalIf,
	1 << 14: scriptflag.VerifyNullFail,
	1 << 16: scriptflag.EnableSighashForkID,
	1 << 18: scriptflag.Genesis,
	1 << 19: scriptflag.UTXOAfterGenesis,
	1 << 20: scriptflag.Chronicle,
	1 << 21: scriptflag.UTXOAfterChronicle,
}

// unmodelledPolicyVectors are relay-word results the node rejects only under
// its default policy limits on script number size, which the SDK does not
// model. Its default stack memory limit is the SDK's default too.
var unmodelledPolicyVectors = map[string]string{
	"policy/script-number-20000-bytes-minimal|0x3d47ff": "script number policy limit",
	"policy/script-number-10001-bytes-minimal|0x3d47ff": "script number policy limit",
}

// errNodeVectorPanic marks an interpreter panic, which fails a vector whatever
// the node's verdict.
var errNodeVectorPanic = errors.New("interpreter panicked")

// executeNodeVector verifies every input of tx with the SDK, stopping at the
// first failure: with no stack memory limit under consensus rules, as node's
// INT64_MAX consensus default, and with the SDK's default, node's default
// relay policy limit, otherwise. Execute reports a panic, or any other
// internal inconsistency, as ErrInternal; that is returned as
// errNodeVectorPanic.
func executeNodeVector(tx *transaction.Transaction, prevOuts []*transaction.TransactionOutput, flags scriptflag.Flag, consensus bool) error {
	maxStackMemory := interpreter.DefaultMaxStackMemory
	if consensus {
		maxStackMemory = math.MaxInt64
	}
	for i := range tx.Inputs {
		if err := interpreter.NewEngine().Execute(
			interpreter.WithTx(tx, i, prevOuts[i]),
			interpreter.WithFlags(flags),
			interpreter.WithMaxStackMemory(maxStackMemory),
		); err != nil {
			if errs.IsErrorCode(err, errs.ErrInternal) {
				return fmt.Errorf("input %d: %w: %w", i, errNodeVectorPanic, err)
			}
			return fmt.Errorf("input %d: %w", i, err)
		}
	}
	return nil
}

// TestNodeVectorsAgainstBDK replays the interpreter's node vector corpus
// through bitcoin-sv's own interpreter (GoBDK) and the SDK: the node must
// still produce every recorded verdict, and the SDK must agree with it.
func TestNodeVectorsAgainstBDK(t *testing.T) {
	b, err := os.ReadFile(nodeVectorsFile)
	require.NoError(t, err)
	var corpus struct {
		Vectors []nodeVector `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(b, &corpus))
	require.NotEmpty(t, corpus.Vectors)

	validator, err := bdk.NewValidator("main")
	require.NoError(t, err)

	for _, v := range corpus.Vectors {
		for _, r := range v.Results {
			t.Run(v.ID+"/"+r.Word, func(t *testing.T) {
				if v.Heavy && testing.Short() {
					t.Skip("heavy vector skipped in short mode")
				}
				word, err := strconv.ParseUint(r.Word, 0, 32)
				require.NoError(t, err)

				tx, err := transaction.NewTransactionFromHex(v.Tx)
				require.NoError(t, err)
				require.Len(t, v.Locks, len(tx.Inputs))
				require.Len(t, v.Sats, len(tx.Inputs))
				prevOuts := make([]*transaction.TransactionOutput, len(tx.Inputs))
				words := make([]uint32, len(tx.Inputs))
				for i, in := range tx.Inputs {
					lock, err := hex.DecodeString(v.Locks[i])
					require.NoError(t, err)
					prevOuts[i] = &transaction.TransactionOutput{LockingScript: script.NewFromBytes(lock), Satoshis: v.Sats[i]}
					in.SetSourceTxOutput(prevOuts[i])
					words[i] = uint32(word)
				}

				nodeErr := validator.VerifyScriptWithCustomFlags(tx, v.CoinHeights, v.Spend, r.Consensus, words)
				nodeValid := nodeErr == nil
				require.Equal(t, r.Valid, nodeValid, "%s: node verdict changed (%v)", v.Name, nodeErr)

				key := v.ID + "|" + r.Word
				if reason, ok := unmodelledPolicyVectors[key]; ok {
					t.Skipf("unmodelled node policy: %s", reason)
				}

				var flags scriptflag.Flag
				for bit := uint32(1); bit != 0; bit <<= 1 {
					if uint32(word)&bit != 0 {
						f, ok := nodeWordFlags[bit]
						require.True(t, ok, "node flag bit 0x%x has no SDK counterpart", bit)
						flags |= f
					}
				}
				sdkErr := executeNodeVector(tx, prevOuts, flags, r.Consensus)
				require.NotErrorIs(t, sdkErr, errNodeVectorPanic, v.Name)
				require.Equal(t, nodeValid, sdkErr == nil, "%s: SDK (%v) disagrees with node (%v)", v.Name, sdkErr, nodeErr)
			})
		}
	}
}
