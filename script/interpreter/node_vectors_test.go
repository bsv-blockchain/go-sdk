package interpreter

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/errs"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// harnessNodeVectorsFile holds every case verified against bitcoin-sv
// (GoBDK) while fixing GHSA-rh54-8fpg-8wwf, each with bitcoin-sv 879fc8b42's
// verdict for one or more per-input flag words. transaction/bdk replays the
// same file through the node itself.
const harnessNodeVectorsFile = "testdata/node_vectors.json"

type harnessNodeVectorResult struct {
	Word      string `json:"word"`
	Consensus bool   `json:"consensus"`
	Valid     bool   `json:"valid"`
	NodeError string `json:"nodeError"`
}

type harnessNodeVector struct {
	ID          string                    `json:"id"`
	Name        string                    `json:"name"`
	Source      string                    `json:"source"`
	Heavy       bool                      `json:"heavy"`
	Tx          string                    `json:"tx"`
	Locks       []string                  `json:"locks"`
	Sats        []uint64                  `json:"sats"`
	CoinHeights []int32                   `json:"coinHeights"`
	Spend       int32                     `json:"spend"`
	Results     []harnessNodeVectorResult `json:"results"`
}

// harnessNodeWordFlags maps bitcoin-sv's script-verify flag bits
// (script/script_flags.h) to the SDK's flags.
var harnessNodeWordFlags = map[uint32]scriptflag.Flag{
	1 << 0:  scriptflag.Bip16,                     // SCRIPT_VERIFY_P2SH
	1 << 1:  scriptflag.VerifyStrictEncoding,      // SCRIPT_VERIFY_STRICTENC
	1 << 2:  scriptflag.VerifyDERSignatures,       // SCRIPT_VERIFY_DERSIG
	1 << 3:  scriptflag.VerifyLowS,                // SCRIPT_VERIFY_LOW_S
	1 << 4:  scriptflag.StrictMultiSig,            // SCRIPT_VERIFY_NULLDUMMY
	1 << 5:  scriptflag.VerifySigPushOnly,         // SCRIPT_VERIFY_SIGPUSHONLY
	1 << 6:  scriptflag.VerifyMinimalData,         // SCRIPT_VERIFY_MINIMALDATA
	1 << 7:  scriptflag.DiscourageUpgradableNops,  // SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS
	1 << 8:  scriptflag.VerifyCleanStack,          // SCRIPT_VERIFY_CLEANSTACK
	1 << 9:  scriptflag.VerifyCheckLockTimeVerify, // SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
	1 << 10: scriptflag.VerifyCheckSequenceVerify, // SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
	1 << 13: scriptflag.VerifyMinimalIf,           // SCRIPT_VERIFY_MINIMALIF
	1 << 14: scriptflag.VerifyNullFail,            // SCRIPT_VERIFY_NULLFAIL
	1 << 16: scriptflag.EnableSighashForkID,       // SCRIPT_ENABLE_SIGHASH_FORKID
	1 << 18: scriptflag.Genesis,                   // SCRIPT_GENESIS
	1 << 19: scriptflag.UTXOAfterGenesis,          // SCRIPT_UTXO_AFTER_GENESIS
	1 << 20: scriptflag.Chronicle,                 // SCRIPT_CHRONICLE
	1 << 21: scriptflag.UTXOAfterChronicle,        // SCRIPT_UTXO_AFTER_CHRONICLE
}

// harnessNodeWordToFlags converts a node flag word to SDK flags, failing on
// bits the SDK does not model.
func harnessNodeWordToFlags(word uint32) (scriptflag.Flag, error) {
	var flags scriptflag.Flag
	for bit := uint32(1); bit != 0; bit <<= 1 {
		if word&bit == 0 {
			continue
		}
		f, ok := harnessNodeWordFlags[bit]
		if !ok {
			return 0, fmt.Errorf("node flag bit 0x%x has no SDK counterpart", bit)
		}
		flags |= f
	}
	return flags, nil
}

// harnessNodeVectorKey identifies one (vector, word) result in
// harnessPolicyVectors.
func harnessNodeVectorKey(id, word string) string {
	return id + "|" + word
}

// harnessPolicyVectors lists relay-word results the node rejects only
// because of its default policy limits on script and script number size,
// which the SDK does not model. Its default stack memory limit is the SDK's
// DefaultMaxStackMemory, so those results are checked (see harnessExecute).
var harnessPolicyVectors = map[string]string{
	"policy/script-number-20000-bytes-minimal|0x3d47ff": "default 10,000-byte script number policy limit",
	"policy/script-number-10001-bytes-minimal|0x3d47ff": "default 10,000-byte script number policy limit",
}

// harnessLoadNodeVectors reads the corpus.
func harnessLoadNodeVectors(t *testing.T) []harnessNodeVector {
	t.Helper()
	b, err := os.ReadFile(harnessNodeVectorsFile)
	if err != nil {
		t.Fatalf("read %s: %v", harnessNodeVectorsFile, err)
	}
	var corpus struct {
		Vectors []harnessNodeVector `json:"vectors"`
	}
	if err := json.Unmarshal(b, &corpus); err != nil {
		t.Fatalf("decode %s: %v", harnessNodeVectorsFile, err)
	}
	return corpus.Vectors
}

// harnessNodeVectorTx rebuilds the spending transaction and the outputs it
// spends.
func harnessNodeVectorTx(v harnessNodeVector) (*transaction.Transaction, []*transaction.TransactionOutput, error) {
	tx, err := transaction.NewTransactionFromHex(v.Tx)
	if err != nil {
		return nil, nil, err
	}
	if len(v.Locks) != len(tx.Inputs) || len(v.Sats) != len(tx.Inputs) {
		return nil, nil, fmt.Errorf("%d inputs but %d locks and %d sats", len(tx.Inputs), len(v.Locks), len(v.Sats))
	}
	prevOuts := make([]*transaction.TransactionOutput, len(tx.Inputs))
	for i, in := range tx.Inputs {
		lock, err := hex.DecodeString(v.Locks[i])
		if err != nil {
			return nil, nil, err
		}
		prevOuts[i] = &transaction.TransactionOutput{LockingScript: script.NewFromBytes(lock), Satoshis: v.Sats[i]}
		in.SetSourceTxOutput(prevOuts[i])
	}
	return tx, prevOuts, nil
}

// errHarnessPanic marks an interpreter panic, which fails a vector whatever
// the node's verdict.
var errHarnessPanic = errors.New("interpreter panicked")

// harnessExecute verifies every input of tx like the node does, stopping at
// the first failure: under consensus rules with no stack memory limit, as
// node's INT64_MAX consensus default, otherwise under the default relay
// policy limit, which is the SDK's default too. Execute reports a panic, or
// any other internal inconsistency, as ErrInternal; that is returned as
// errHarnessPanic so it fails the vector even when the node's verdict is
// also invalid.
func harnessExecute(tx *transaction.Transaction, prevOuts []*transaction.TransactionOutput, flags scriptflag.Flag, consensus bool) error {
	maxStackMemory := DefaultMaxStackMemory
	if consensus {
		maxStackMemory = math.MaxInt64
	}
	for i := range tx.Inputs {
		if err := NewEngine().Execute(WithTx(tx, i, prevOuts[i]), WithFlags(flags), WithMaxStackMemory(maxStackMemory)); err != nil {
			if errs.IsErrorCode(err, errs.ErrInternal) {
				return fmt.Errorf("input %d: %w: %w", i, errHarnessPanic, err)
			}
			return fmt.Errorf("input %d: %w", i, err)
		}
	}
	return nil
}

// TestNodeVectors checks that the SDK's verdict equals bitcoin-sv's for every
// word of every vector in testdata/node_vectors.json, verifying every input
// like the node does.
func TestNodeVectors(t *testing.T) {
	var ran, policy int
	for _, v := range harnessLoadNodeVectors(t) {
		for _, r := range v.Results {
			t.Run(v.ID+"/"+r.Word, func(t *testing.T) {
				if v.Heavy && testing.Short() {
					t.Skip("heavy vector skipped in short mode")
				}
				key := harnessNodeVectorKey(v.ID, r.Word)
				if reason, ok := harnessPolicyVectors[key]; ok {
					policy++
					t.Skipf("unmodelled node policy: %s", reason)
				}
				word, err := strconv.ParseUint(r.Word, 0, 32)
				if err != nil {
					t.Fatalf("bad word %q: %v", r.Word, err)
				}
				flags, err := harnessNodeWordToFlags(uint32(word))
				if err != nil {
					t.Fatal(err)
				}
				tx, prevOuts, err := harnessNodeVectorTx(v)
				if err != nil {
					t.Fatal(err)
				}
				sdkErr := harnessExecute(tx, prevOuts, flags, r.Consensus)
				valid := sdkErr == nil
				panicked := errors.Is(sdkErr, errHarnessPanic)
				ran++
				if panicked {
					t.Fatalf("%s: %v", v.Name, sdkErr)
				}
				if valid != r.Valid {
					t.Errorf("%s: SDK valid=%v (%v), node valid=%v (%s)", v.Name, valid, sdkErr, r.Valid, r.NodeError)
				}
			})
		}
	}
	t.Logf("node vectors: %d checked, %d unmodelled policy", ran, policy)
}
