// Package scripts_test runs the ts-stack script-engine conformance corpus
// (sdk/scripts/evaluation.json plus the script-* regression files) against
// the Go script/interpreter packages, mirroring the assertions made by the
// TS reference runner's sdk dispatcher (see
// ts-stack/conformance/runner/ts/dispatchers/sdk.ts and sdkHelpers.ts) and
// its regressions dispatcher (regressions.ts).
package scripts_test

import (
	"encoding/hex"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
)

// asMap decodes a vector's raw input/expected JSON into a generic map, the
// same shape the TS dispatchers work with (Record<string, unknown>).
type jsonMap = map[string]interface{}

func getString(m jsonMap, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getBool(m jsonMap, key string) bool {
	v, ok := m[key].(bool)
	return ok && v
}

// getNumber returns m[key] as a float64 (the type every JSON number decodes
// to), or fallback when the key is absent or not a number.
func getNumber(m jsonMap, key string, fallback float64) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	return fallback
}

func getInt(m jsonMap, key string, fallback int) int {
	return int(getNumber(m, key, float64(fallback)))
}

func getStringSlice(m jsonMap, key string) []string {
	raw, ok := m[key].([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func hasKey(m jsonMap, key string) bool {
	_, ok := m[key]
	return ok
}

// hexFillByte parses the "0xNN" fill-byte strings the vectors use (e.g.
// "fill_byte": "0xab") into the raw byte, mirroring parseFillByte in
// sdkHelpers.ts.
func hexFillByte(t testing.TB, s string) byte {
	t.Helper()
	if len(s) < 2 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X') {
		t.Fatalf("invalid fill byte literal %q", s)
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil || len(b) != 1 {
		t.Fatalf("invalid fill byte literal %q: %v", s, err)
	}
	return b[0]
}

// flagBits is the TS Spend#hasFlag name -> Go scriptflag.Flag mapping used
// by every fixture that carries an explicit CSV/array of named verify flags
// (flags_csv / flags / flag_strings). Names follow the ones the ts-stack
// conformance generator uses (bitcoind-style SCRIPT_VERIFY_* short names, see
// Spend.ts's #hasFlag call sites) plus the BSV-specific UTXO_AFTER_* names.
var flagBits = map[string]scriptflag.Flag{
	"P2SH":                       scriptflag.Bip16,
	"STRICTENC":                  scriptflag.VerifyStrictEncoding,
	"DERSIG":                     scriptflag.VerifyDERSignatures,
	"LOW_S":                      scriptflag.VerifyLowS,
	"NULLDUMMY":                  scriptflag.StrictMultiSig,
	"SIGPUSHONLY":                scriptflag.VerifySigPushOnly,
	"MINIMALDATA":                scriptflag.VerifyMinimalData,
	"DISCOURAGE_UPGRADABLE_NOPS": scriptflag.DiscourageUpgradableNops,
	"CLEANSTACK":                 scriptflag.VerifyCleanStack,
	"CHECKLOCKTIMEVERIFY":        scriptflag.VerifyCheckLockTimeVerify,
	"CHECKSEQUENCEVERIFY":        scriptflag.VerifyCheckSequenceVerify,
	"SIGHASH_FORKID":             scriptflag.EnableSighashForkID,
	"MINIMALIF":                  scriptflag.VerifyMinimalIf,
	"NULLFAIL":                   scriptflag.VerifyNullFail,
	"UTXO_AFTER_GENESIS":         scriptflag.UTXOAfterGenesis,
	// GENESIS is the vectors' alias for UTXO_AFTER_GENESIS: TS's
	// #isAfterGenesis() treats the two flags identically (Spend.ts).
	"GENESIS": scriptflag.UTXOAfterGenesis,
	// UTXO_AFTER_CHRONICLE always implies UTXO_AFTER_GENESIS in the Go
	// engine (scriptflag.UTXOAfterChronicle's doc comment), which matches
	// #isAfterGenesis() also returning true whenever UTXO_AFTER_CHRONICLE
	// is set.
	"UTXO_AFTER_CHRONICLE": scriptflag.UTXOAfterGenesis | scriptflag.UTXOAfterChronicle,
	"NONE":                 0,
}

// parseFlagsCSV turns a comma-separated verify-flags string (the vectors'
// flags_csv field) into the equivalent scriptflag bitmask.
func parseFlagsCSV(t testing.TB, csv string) scriptflag.Flag {
	t.Helper()
	return parseFlagList(t, splitCSV(csv))
}

func splitCSV(csv string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(csv); i++ {
		if i == len(csv) || csv[i] == ',' {
			if i > start {
				out = append(out, csv[start:i])
			}
			start = i + 1
		}
	}
	return out
}

// parseFlagList is parseFlagsCSV for an already-split flag name list (the
// vectors' flag_sets entries).
func parseFlagList(t testing.TB, names []string) scriptflag.Flag {
	t.Helper()
	var f scriptflag.Flag
	for _, name := range names {
		bit, ok := flagBits[name]
		if !ok {
			t.Fatalf("unknown verify flag %q", name)
		}
		f |= bit
	}
	return f
}

// relaxedFlags reproduces the Go equivalent of ts-stack's Spend when
// constructed WITHOUT an explicit verifyFlags set (Spend.ts's
// #hasExplicitFlags() branch is false): P2SH/BIP16 evaluation is never
// enabled in that mode (Spend.ts's #hasFlag always returns false without an
// explicit set), STRICTENC/DERSIG are always enforced, and the maleability
// checks (MINIMALDATA/LOW_S/NULLDUMMY/SIGPUSHONLY/CLEANSTACK) plus the
// after-genesis/after-chronicle gates all follow the single isRelaxed
// override (see Spend.ts #isRelaxed/#isAfterGenesis/#shouldEnforce*).
func relaxedFlags(isRelaxed bool) scriptflag.Flag {
	f := scriptflag.VerifyStrictEncoding | scriptflag.VerifyDERSignatures
	if isRelaxed {
		f |= scriptflag.UTXOAfterGenesis | scriptflag.UTXOAfterChronicle
		return f
	}
	f |= scriptflag.VerifyMinimalData | scriptflag.VerifyLowS | scriptflag.StrictMultiSig |
		scriptflag.VerifySigPushOnly | scriptflag.VerifyCleanStack
	// The Go engine refuses VerifyCleanStack without Bip16 (thread.go's
	// apply() treats that combination as invalid, matching Bitcoin Core's own
	// `!CLEANSTACK || P2SH` assertion in VerifyScript). ts-stack's Spend has
	// no such guard and happily enforces CLEANSTACK on its own, so add Bip16
	// here purely to satisfy the Go engine's precondition; none of the
	// fixtures that reach this path are P2SH scripts, so it has no effect on
	// their evaluation.
	f |= scriptflag.Bip16
	return f
}
