package scripts_test

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
)

// TestRegressions runs the standalone script-* regression vector files,
// mirroring ts-stack's regressions dispatcher (see
// ts-stack/conformance/runner/ts/dispatchers/regressions.ts). Each file
// documents a specific historical SDK bug; the Go engine is checked against
// the corrected behaviour the vectors encode.
func TestRegressions(t *testing.T) {
	for _, rel := range []string{
		"regressions/script-fromasm-numeric-token.json",
		"regressions/script-lshift-truncation.json",
		"regressions/script-shift-endianness.json",
		"regressions/script-writebin-empty.json",
	} {
		t.Run(rel, func(t *testing.T) {
			f := conformance.Load(t, rel)
			conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
				if reason, ok := regressionGoGaps[v.ID]; ok {
					conformance.GoGap(t, reason)
					return
				}
				var input, expected jsonMap
				v.DecodeInput(t, &input)
				v.DecodeExpected(t, &expected)
				dispatchRegression(t, input, expected)
			})
		})
	}
}

// regressionGoGaps declares regression vectors go-sdk deliberately does not
// match ts-stack's reference SDK on: a maintainer-decision-pending GoGap per
// this repo's conformance policy, not missing functionality. See
// regressionWriteBinToASM's doc comment for the full explanation.
var regressionGoGaps = map[string]string{
	"regression.script.writebin-empty.0001": "maintainer decision pending: writeBin([]).toASM() is expected to be \"OP_0\", but go-sdk's script.OpCodeValues reverse-lookup deliberately renders opcode 0x00 as \"OP_FALSE\" (not \"OP_0\"), the same pre-existing, already-tested naming divergence as evaluation vector script-018 (see its GoGap reason in evaluation_conformance_test.go for the full tradeoff: flipping OpCodeValues to ts-stack's names breaks ~10 existing, intentionally-pinned assertions in script/script_test.go's TestScriptToAsm/TestScript_MinPushSize).",
}

func dispatchRegression(t *testing.T, input, expected jsonMap) {
	t.Helper()
	switch getString(input, "operation") {
	case "fromASM_toHex":
		regressionFromASMToHex(t, input, expected)
	case "op_lshift":
		regressionShift(t, input, expected, true)
	case "op_rshift":
		regressionShift(t, input, expected, false)
	case "script_writeBin_toASM":
		regressionWriteBinToASM(t, input, expected)
	case "script_writeBin_toHex":
		regressionWriteBinToHex(t, input, expected)
	default:
		t.Fatalf("unrecognized regression operation: %+v", input)
	}
}

// regression.script.fromasm-numeric-token: a bare numeric-looking ASM token
// ("76") is a 1-byte data push, never confused with the identically-valued
// opcode byte (OP_DUP is only produced by the literal "OP_DUP" token).
func regressionFromASMToHex(t *testing.T, input, expected jsonMap) {
	t.Helper()
	s, err := script.NewFromASM(getString(input, "asm"))
	if err != nil {
		t.Fatalf("NewFromASM: %v", err)
	}
	if got, want := s.String(), getString(expected, "hex"); got != want {
		t.Errorf("hex = %q, want %q", got, want)
	}
}

// regression.script.lshift-truncation / regression.script.shift-endianness:
// OP_LSHIFT/OP_RSHIFT must truncate the shifted result to the operand's
// original byte length and preserve big-endian byte order. This runs the
// actual interpreter opcodes (not a reimplementation) via a script of the
// form "<value> <shift> OP_?SHIFT <expected> OP_EQUAL", so a wrong result or
// a wrong length both surface as a script-evaluation failure.
func regressionShift(t *testing.T, input, expected jsonMap, isLeft bool) {
	t.Helper()
	valueBytes, err := hex.DecodeString(getString(input, "value_hex"))
	if err != nil {
		t.Fatalf("decode value_hex: %v", err)
	}
	shiftBits := getInt(input, "shift_bits", 0)
	resultBytes, err := hex.DecodeString(getString(expected, "result_hex"))
	if err != nil {
		t.Fatalf("decode result_hex: %v", err)
	}
	if want := getInt(expected, "result_length_bytes", 0); len(resultBytes) != want {
		t.Fatalf("fixture inconsistency: result_hex is %d bytes, result_length_bytes says %d", len(resultBytes), want)
	}

	lockingScript := &script.Script{}
	if buildErr := lockingScript.AppendPushData(valueBytes); buildErr != nil {
		t.Fatalf("AppendPushData(value): %v", buildErr)
	}
	var bi big.Int
	bi.SetInt64(int64(shiftBits))
	if buildErr := lockingScript.AppendBigInt(bi); buildErr != nil {
		t.Fatalf("AppendBigInt(shift): %v", buildErr)
	}
	if isLeft {
		if buildErr := lockingScript.AppendOpcodes(script.OpLSHIFT); buildErr != nil {
			t.Fatalf("AppendOpcodes(OP_LSHIFT): %v", buildErr)
		}
	} else {
		if buildErr := lockingScript.AppendOpcodes(script.OpRSHIFT); buildErr != nil {
			t.Fatalf("AppendOpcodes(OP_RSHIFT): %v", buildErr)
		}
	}
	if buildErr := lockingScript.AppendPushData(resultBytes); buildErr != nil {
		t.Fatalf("AppendPushData(result): %v", buildErr)
	}
	if buildErr := lockingScript.AppendOpcodes(script.OpEQUAL); buildErr != nil {
		t.Fatalf("AppendOpcodes(OP_EQUAL): %v", buildErr)
	}

	err = interpreter.NewEngine().Execute(interpreter.WithScripts(lockingScript, &script.Script{}))
	if err != nil {
		t.Errorf("shift(%s, %d) did not equal expected %s: %v",
			getString(input, "value_hex"), shiftBits, getString(expected, "result_hex"), err)
	}
}

// regression.script.writebin-empty: Script.writeBin([]) must push OP_0
// (opcode 0x00), which serializes as "00" in hex and "OP_0" in ASM.
//
// NOTE: go-sdk's OpCodeValues reverse-lookup deliberately renders opcode
// 0x00 as "OP_FALSE" (see script_test.go's TestScriptToAsm, which documents
// and tests "go-sdk canonical names" such as OP_TRUE/OP_FALSE for the same
// byte values ts-stack's SDK names OP_1/OP_0). That is a pre-existing,
// tested choice in this package, not a bug introduced here, so the
// regression.script.writebin-empty.0001 ASM vector is declared as a GoGap
// (see regressionGoGaps) rather than run through this function; the toHex
// vector (regression.script.writebin-empty.0002) is unaffected by opcode
// naming and still runs normally.
func regressionWriteBinToASM(t *testing.T, input, expected jsonMap) {
	t.Helper()
	s := &script.Script{}
	appendWriteBin(t, s, input)
	if got, want := s.ToASM(), getString(expected, "asm"); got != want {
		t.Errorf("asm = %q, want %q", got, want)
	}
}

func regressionWriteBinToHex(t *testing.T, input, expected jsonMap) {
	t.Helper()
	s := &script.Script{}
	appendWriteBin(t, s, input)
	if got, want := s.String(), getString(expected, "hex"); got != want {
		t.Errorf("hex = %q, want %q", got, want)
	}
}

func appendWriteBin(t *testing.T, s *script.Script, input jsonMap) {
	t.Helper()
	data, err := hex.DecodeString(getString(input, "data_hex"))
	if err != nil {
		t.Fatalf("decode data_hex: %v", err)
	}
	if err := s.AppendPushData(data); err != nil {
		t.Fatalf("AppendPushData: %v", err)
	}
}
