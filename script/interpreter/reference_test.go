// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package interpreter

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/errs"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

var opcodeByName = make(map[string]byte)

//nolint:gochecknoinits // builds the opcode name lookup table used by parseShortForm test helper
func init() {
	// Initialize the opcode name to value map using the contents of the
	// opcode array.  Also add entries for "OP_FALSE", "OP_TRUE", and
	// "OP_NOP2" since they are aliases for "OP_0", "OP_1",
	// and "OP_CHECKLOCKTIMEVERIFY" respectively.
	for _, op := range &opcodeArray {
		opcodeByName[op.Name()] = op.val
	}
	opcodeByName["OP_0"] = script.Op0
	opcodeByName["OP_1"] = script.Op1
	opcodeByName["OP_CHECKLOCKTIMEVERIFY"] = script.OpCHECKLOCKTIMEVERIFY
	opcodeByName["OP_CHECKSEQUENCEVERIFY"] = script.OpCHECKSEQUENCEVERIFY
	opcodeByName["OP_RESERVED"] = script.OpRESERVED
	// Bitcoin Core reference tests use NOP4-NOP8 short names. Since Chronicle
	// repurposed those bytes under Chronicle names (OP_SUBSTR etc.), the NOP
	// aliases are no longer in opcodeArray. Re-add them so parseShortForm can
	// strip "OP_" and produce the short forms "NOP4"-"NOP8".
	opcodeByName["OP_NOP4"] = script.OpNOP4
	opcodeByName["OP_NOP5"] = script.OpNOP5
	opcodeByName["OP_NOP6"] = script.OpNOP6
	opcodeByName["OP_NOP7"] = script.OpNOP7
	opcodeByName["OP_NOP8"] = script.OpNOP8
}

// parseShortForm parses a string as as used in the Bitcoin Core reference tests
// into the script it came from.
//
// The format used for these tests is pretty simple if ad-hoc:
//   - Opcodes other than the push opcodes and unknown are present as
//     either OP_NAME or just NAME
//   - Plain numbers are made into push operations
//   - Numbers beginning with 0x are inserted into the []byte as-is (so
//     0x14 is OP_DATA_20)
//   - Single quoted strings are pushed as data
//   - Anything else is an error
func parseShortForm(scriptStr string) (*script.Script, error) {
	// Only create the short form opcode map once.
	if shortFormOps == nil {
		ops := make(map[string]byte)
		for opcodeName, opcodeValue := range opcodeByName {
			if strings.Contains(opcodeName, "OP_UNKNOWN") {
				continue
			}
			ops[opcodeName] = opcodeValue

			// The opcodes named OP_# can't have the OP_ prefix
			// stripped or they would conflict with the plain
			// numbers.  Also, since OP_FALSE and OP_TRUE are
			// aliases for the OP_0, and OP_1, respectively, they
			// have the same value, so detect those by name and
			// allow them.
			if (opcodeName == "OP_FALSE" || opcodeName == "OP_TRUE") ||
				(opcodeValue != script.Op0 && (opcodeValue < script.Op1 ||
					opcodeValue > script.Op16)) {

				ops[strings.TrimPrefix(opcodeName, "OP_")] = opcodeValue
			}
		}
		shortFormOps = ops
	}

	// Split only does one separator so convert all \n and tab into  space.
	scriptStr = strings.ReplaceAll(scriptStr, "\n", " ")
	scriptStr = strings.ReplaceAll(scriptStr, "\t", " ")
	tokens := strings.Split(scriptStr, " ")

	var scr script.Script
	for _, tok := range tokens {
		if len(tok) == 0 {
			continue
		}
		// if parses as a plain number
		if num, err := strconv.ParseInt(tok, 10, 64); err == nil {
			if num == 0 {
				_ = scr.AppendOpcodes(script.Op0)
			} else if num == -1 || (1 <= num && num <= 16) {
				_ = scr.AppendOpcodes((script.Op1 - 1) + byte(num)) //nolint:gosec // G115 -- num is bounds-checked to [1,16] above
			} else {
				n := &ScriptNumber{Val: big.NewInt(num)}
				_ = scr.AppendPushData(n.Bytes())
			}
			continue
		} else if bts, err := parseHex(tok); err == nil {
			// Concatenate the bytes manually since the test code
			// intentionally creates scripts that are too large and
			// would cause the builder to error otherwise.
			scr = append(scr, bts...)
		} else if len(tok) >= 2 &&
			tok[0] == '\'' && tok[len(tok)-1] == '\'' {
			_ = scr.AppendPushData([]byte(tok[1 : len(tok)-1]))
		} else if code, ok := shortFormOps[tok]; ok {
			scr = append(scr, code)
		} else {
			return nil, fmt.Errorf("bad token %q", tok)
		}

	}

	return &scr, nil
}

// scriptTest is one parsed script_tests.json vector.
type scriptTest struct {
	name      string
	amount    int64 // satoshis
	txVersion uint32
	sigScript string
	pkScript  string
	flags     string
	result    string
}

// parseScriptTest parses one script_tests.json vector. bitcoin-sv's format
// (test/script_tests.cpp script_json_test) is
//
//	[[wit..., amount]?, txnVersion, scriptSig, scriptPubKey, flags, expected_scripterror, comment?]
//
// where the node reads the amount (in BTC) from the array's first element and
// txnVersion is the spending transaction's version as a decimal string. The
// txnVersion field is optional here so that copies of the corpus predating it
// (version 1 implied) still load.
func parseScriptTest(test []any) (scriptTest, error) {
	var st scriptTest
	fields := test
	if len(fields) > 0 {
		if wit, ok := fields[0].([]any); ok {
			if len(wit) == 0 {
				return st, errors.New("empty witness/amount array")
			}
			f, ok := wit[0].(float64)
			if !ok {
				return st, errors.New("amount is not a number")
			}
			st.amount = int64(math.Round(f * 1e8))
			fields = fields[1:]
		}
	}

	strs := make([]string, len(fields))
	for i, f := range fields {
		s, ok := f.(string)
		if !ok {
			return st, fmt.Errorf("field %d is not a string", i)
		}
		strs[i] = s
	}

	st.txVersion = 1
	if len(strs) >= 5 {
		if _, err := parseExpectedResult(strs[4]); err == nil {
			v, err := strconv.ParseInt(strs[0], 10, 32)
			if err != nil {
				return st, fmt.Errorf("bad txnVersion %q: %w", strs[0], err)
			}
			st.txVersion = uint32(int32(v)) //nolint:gosec // G115 -- nVersion is a signed int32 on the wire
			strs = strs[1:]
		}
	}
	if len(strs) < 4 || len(strs) > 5 {
		return st, fmt.Errorf("invalid test length %d", len(test))
	}
	st.sigScript, st.pkScript, st.flags, st.result = strs[0], strs[1], strs[2], strs[3]

	// Use the comment for the test name if one is specified, otherwise,
	// construct the name based on the signature script, public key script,
	// and flags.
	if len(strs) == 5 {
		st.name = fmt.Sprintf("test (%s)", strs[4])
	} else {
		st.name = fmt.Sprintf("test ([%s, %s, %s])", strs[0], strs[1], strs[2])
	}
	return st, nil
}

// parse hex string into a []byte.
func parseHex(tok string) ([]byte, error) {
	if !strings.HasPrefix(tok, "0x") {
		return nil, errors.New("not a hex number")
	}
	return hex.DecodeString(tok[2:])
}

// shortFormOps holds a map of opcode names to values for use in short form
// parsing.  It is declared here so it only needs to be created once.
var shortFormOps map[string]byte

// parseScriptFlags parses the provided flags string from the format used in the
// reference tests into ScriptFlags suitable for use in the script engine.
func parseScriptFlags(flagStr string) (scriptflag.Flag, error) {
	var flags scriptflag.Flag

	sFlags := strings.Split(flagStr, ",")
	for _, flag := range sFlags {
		switch flag {
		case "":
			// Nothing.
		case "CHECKLOCKTIMEVERIFY":
			flags |= scriptflag.VerifyCheckLockTimeVerify
		case "CHECKSEQUENCEVERIFY":
			flags |= scriptflag.VerifyCheckSequenceVerify
		case "CLEANSTACK":
			flags |= scriptflag.VerifyCleanStack
		case "DERSIG":
			flags |= scriptflag.VerifyDERSignatures
		case "DISCOURAGE_UPGRADABLE_NOPS":
			flags |= scriptflag.DiscourageUpgradableNops
		case "LOW_S":
			flags |= scriptflag.VerifyLowS
		case "MINIMALDATA":
			flags |= scriptflag.VerifyMinimalData
		case "NONE":
			// Nothing.
		case "NULLDUMMY":
			flags |= scriptflag.StrictMultiSig
		case "NULLFAIL":
			flags |= scriptflag.VerifyNullFail
		case "P2SH":
			flags |= scriptflag.Bip16
		case "SIGPUSHONLY":
			flags |= scriptflag.VerifySigPushOnly
		case "STRICTENC":
			flags |= scriptflag.VerifyStrictEncoding
		case "UTXO_AFTER_GENESIS":
			flags |= scriptflag.UTXOAfterGenesis
		case "UTXO_AFTER_CHRONICLE":
			// One bit, like node's ParseScriptFlags: without
			// UTXO_AFTER_GENESIS it is SCRIPT_ERR_INVALID_FLAGS.
			flags |= scriptflag.UTXOAfterChronicle
		case "GENESIS":
			flags |= scriptflag.Genesis
		case "CHRONICLE":
			flags |= scriptflag.Genesis | scriptflag.Chronicle
		case "MINIMALIF":
			flags |= scriptflag.VerifyMinimalIf
		case "SIGHASH_FORKID":
			flags |= scriptflag.EnableSighashForkID
		default:
			return flags, fmt.Errorf("invalid flag: %s", flag)
		}
	}
	return flags, nil
}

// parseExpectedResult parses the provided expected result string into allowed
// script error codes.  An error is returned if the expected result string is
// not supported.
func parseExpectedResult(expected string) ([]errs.ErrorCode, error) {
	switch expected {
	case "OK":
		return nil, nil
	case "INVALID_NUMBER_RANGE", "SPLIT_RANGE":
		return []errs.ErrorCode{errs.ErrNumberTooBig, errs.ErrNumberTooSmall}, nil
	case "OPERAND_SIZE":
		return []errs.ErrorCode{errs.ErrInvalidInputLength}, nil
	case "PUBKEYTYPE":
		return []errs.ErrorCode{errs.ErrPubKeyType}, nil
	case "SIG_DER":
		return []errs.ErrorCode{
			errs.ErrSigTooShort, errs.ErrSigTooLong,
			errs.ErrSigInvalidSeqID, errs.ErrSigInvalidDataLen, errs.ErrSigMissingSTypeID,
			errs.ErrSigMissingSLen, errs.ErrSigInvalidSLen,
			errs.ErrSigInvalidRIntID, errs.ErrSigZeroRLen, errs.ErrSigNegativeR,
			errs.ErrSigTooMuchRPadding, errs.ErrSigInvalidSIntID,
			errs.ErrSigZeroSLen, errs.ErrSigNegativeS, errs.ErrSigTooMuchSPadding,
			errs.ErrInvalidSigHashType,
		}, nil
	case "EVAL_FALSE":
		// The node checks the final stack element before CLEANSTACK
		// (VerifyScript), the SDK after, so a false top element with extra
		// items below it reports ErrCleanStack; both reject.
		return []errs.ErrorCode{errs.ErrEvalFalse, errs.ErrEmptyStack, errs.ErrCleanStack}, nil
	case "EQUALVERIFY":
		return []errs.ErrorCode{errs.ErrEqualVerify}, nil
	case "NULLFAIL":
		return []errs.ErrorCode{errs.ErrNullFail}, nil
	case "SIG_HIGH_S":
		return []errs.ErrorCode{errs.ErrSigHighS}, nil
	case "SIG_HASHTYPE":
		return []errs.ErrorCode{errs.ErrInvalidSigHashType}, nil
	case "ILLEGAL_CHRONICLE":
		return []errs.ErrorCode{errs.ErrIllegalChronicle}, nil
	case "MISSING_FORKID", "MUST_USE_FORKID":
		// script_tests.cpp names SCRIPT_ERR_MUST_USE_FORKID "MISSING_FORKID".
		return []errs.ErrorCode{errs.ErrMustUseForkID}, nil
	case "BIG_INT":
		return []errs.ErrorCode{errs.ErrBigInt}, nil
	case "INVALID_FLAGS":
		return []errs.ErrorCode{errs.ErrInvalidFlags}, nil
	case "IMPOSSIBLE_ENCODING":
		// OP_NUM2BIN whose value does not fit the requested size.
		return []errs.ErrorCode{errs.ErrNumberTooSmall}, nil
	case "CHECKMULTISIGVERIFY":
		return []errs.ErrorCode{errs.ErrCheckMultiSigVerify}, nil
	case "NUMEQUALVERIFY":
		return []errs.ErrorCode{errs.ErrNumEqualVerify}, nil
	case "NONCOMPRESSED_PUBKEY":
		return []errs.ErrorCode{errs.ErrPubKeyType}, nil
	case "UNKNOWN_ERROR":
		return []errs.ErrorCode{errs.ErrInternal}, nil
	case "SIG_NULLDUMMY":
		return []errs.ErrorCode{errs.ErrSigNullDummy}, nil
	case "SIG_PUSHONLY":
		return []errs.ErrorCode{errs.ErrNotPushOnly}, nil
	case "CLEANSTACK":
		return []errs.ErrorCode{errs.ErrCleanStack}, nil
	case "BAD_OPCODE":
		return []errs.ErrorCode{errs.ErrReservedOpcode, errs.ErrMalformedPush}, nil
	case "UNBALANCED_CONDITIONAL":
		return []errs.ErrorCode{
			errs.ErrUnbalancedConditional,
			errs.ErrInvalidStackOperation,
		}, nil
	case "OP_RETURN":
		return []errs.ErrorCode{errs.ErrEarlyReturn}, nil
	case "VERIFY":
		return []errs.ErrorCode{errs.ErrVerify}, nil
	case "INVALID_STACK_OPERATION", "INVALID_ALTSTACK_OPERATION":
		return []errs.ErrorCode{errs.ErrInvalidStackOperation}, nil
	case "DISABLED_OPCODE":
		return []errs.ErrorCode{errs.ErrDisabledOpcode}, nil
	case "DISCOURAGE_UPGRADABLE_NOPS":
		return []errs.ErrorCode{errs.ErrDiscourageUpgradableNOPs}, nil
	case "SCRIPTNUM_OVERFLOW":
		return []errs.ErrorCode{errs.ErrNumberTooBig}, nil
	case "NUMBER_SIZE":
		return []errs.ErrorCode{errs.ErrNumberTooBig, errs.ErrNumberTooSmall}, nil
	case "PUSH_SIZE":
		// OP_NUM2BIN reports an out-of-range size as SCRIPT_ERR_PUSH_SIZE on
		// the node and as ErrNumberTooBig/ErrNumberTooSmall in the SDK.
		return []errs.ErrorCode{errs.ErrElementTooBig, errs.ErrNumberTooBig, errs.ErrNumberTooSmall}, nil
	case "OP_COUNT":
		return []errs.ErrorCode{errs.ErrTooManyOperations}, nil
	case "STACK_SIZE":
		return []errs.ErrorCode{errs.ErrStackOverflow}, nil
	case "SCRIPT_SIZE":
		return []errs.ErrorCode{errs.ErrScriptTooBig}, nil
	case "ELEMENT_SIZE":
		return []errs.ErrorCode{errs.ErrElementTooBig}, nil
	case "PUBKEY_COUNT":
		return []errs.ErrorCode{errs.ErrInvalidPubKeyCount}, nil
	case "SIG_COUNT":
		return []errs.ErrorCode{errs.ErrInvalidSignatureCount}, nil
	case "MINIMALDATA":
		return []errs.ErrorCode{errs.ErrMinimalData}, nil
	case "MINIMALIF":
		return []errs.ErrorCode{errs.ErrMinimalIf}, nil
	case "NEGATIVE_LOCKTIME":
		return []errs.ErrorCode{errs.ErrNegativeLockTime}, nil
	case "UNSATISFIED_LOCKTIME":
		return []errs.ErrorCode{errs.ErrUnsatisfiedLockTime}, nil
	case "SCRIPTNUM_MINENCODE":
		return []errs.ErrorCode{errs.ErrMinimalData}, nil
	case "DIV_BY_ZERO", "MOD_BY_ZERO":
		return []errs.ErrorCode{errs.ErrDivideByZero}, nil
	case "CHECKSIGVERIFY":
		return []errs.ErrorCode{errs.ErrCheckSigVerify}, nil
	case "ILLEGAL_FORKID":
		return []errs.ErrorCode{errs.ErrIllegalForkID}, nil
	}

	return nil, fmt.Errorf("unrecognized expected result in test data: %v",
		expected)
}

// createSpendingTx generates a basic spending transaction given the passed
// signature and locking scripts, mirroring bitcoin-sv's
// BuildCreditingTransaction/BuildSpendingTransaction (test/script_tests.cpp):
// the crediting transaction is always version 1, the spend carries txVersion.
func createSpendingTx(sigScript, pkScript *script.Script, outputValue int64, txVersion uint32) *transaction.Transaction {
	coinbaseTx := transaction.NewTransaction()
	coinbaseTx.AddInput(&transaction.TransactionInput{
		SourceTXID:       &chainhash.Hash{},
		SourceTxOutIndex: ^uint32(0),
		UnlockingScript:  script.NewFromBytes([]byte{script.Op0, script.Op0}),
		SequenceNumber:   0xffffffff,
	})
	coinbaseTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      uint64(outputValue), //nolint:gosec // G115 -- test-data amounts are always non-negative
		LockingScript: pkScript,
	})

	spendingTx := &transaction.Transaction{
		Version:  txVersion,
		LockTime: 0,
		Inputs: []*transaction.TransactionInput{{
			SourceTXID:       coinbaseTx.TxID(),
			SourceTxOutIndex: 0,
			UnlockingScript:  sigScript,
			SequenceNumber:   0xffffffff,
		}},
		Outputs: []*transaction.TransactionOutput{{
			Satoshis:      uint64(outputValue), //nolint:gosec // G115 -- test-data amounts are always non-negative
			LockingScript: script.NewFromBytes([]byte{}),
		}},
	}
	spendingTx.Inputs[0].SetSourceTxOutput(&transaction.TransactionOutput{
		LockingScript: pkScript,
	})

	return spendingTx
}

// TestScripts ensures all of the tests in script_tests.json execute with the
// expected results as defined in the test data. data/script_tests.json,
// data/tx_valid.json and data/tx_invalid.json are verbatim copies of
// bitcoin-sv's src/test/data at 879fc8b42.
func TestScripts(t *testing.T) {
	file, err := os.ReadFile("data/script_tests.json")
	if err != nil {
		t.Fatalf("TestScripts: %v\n", err)
	}

	var tests [][]any
	err = json.Unmarshal(file, &tests)
	if err != nil {
		t.Fatalf("TestScripts couldn't Unmarshal: %v", err)
	}

	for i, test := range tests {
		// Skip single line comments.
		if len(test) == 1 {
			continue
		}

		st, err := parseScriptTest(test)
		if err != nil {
			t.Errorf("TestScripts: invalid test #%d: %v", i, err)
			continue
		}
		name := st.name

		scriptSig, err := parseShortForm(st.sigScript)
		if err != nil {
			t.Errorf("%s: can't parse signature script: %v", name, err)
			continue
		}
		scriptPubKey, err := parseShortForm(st.pkScript)
		if err != nil {
			t.Errorf("%s: can't parse public key script: %v", name, err)
			continue
		}
		flags, err := parseScriptFlags(st.flags)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		// DoTest (test/script_tests.cpp) adds P2SH whenever CLEANSTACK is
		// requested, since the node never runs CLEANSTACK without it.
		if flags.HasFlag(scriptflag.VerifyCleanStack) {
			flags |= scriptflag.Bip16
		}

		// Convert the expected result string into the allowed script
		// error codes.  This is necessary because interpreter is more
		// fine grained with its errors than the reference test data, so
		// some of the reference test data errors map to more than one
		// possibility.
		allowedErrorCodes, err := parseExpectedResult(st.result)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}

		// Generate a transaction pair such that one spends from the
		// other and the provided signature and public key scripts are
		// used, then create a new engine to execute the scripts.
		tx := createSpendingTx(scriptSig, scriptPubKey, st.amount, st.txVersion)

		err = NewEngine().Execute(
			WithTx(tx, 0, &transaction.TransactionOutput{LockingScript: scriptPubKey, Satoshis: uint64(st.amount)}), //nolint:gosec // G115 -- test-data amounts are always non-negative
			WithFlags(flags),
		)

		// Ensure there were no errors when the expected result is OK.
		if st.result == "OK" {
			if err != nil {
				t.Errorf("%s failed to execute: %v", name, err)
			}
			continue
		}

		// At this point an error was expected so ensure the result of
		// the execution matches it.
		successRes := false
		for _, code := range allowedErrorCodes {
			if errs.IsErrorCode(err, code) {
				successRes = true
				break
			}
		}
		if !successRes {
			serr := &errs.Error{}
			if ok := errors.As(err, serr); ok {
				t.Errorf("%s: want error codes %v, got %v", name, allowedErrorCodes, serr.ErrorCode)
				continue
			}
			t.Errorf("%s: want error codes %v, got err: %v (%T)", name, allowedErrorCodes, err, err)
			continue
		}
	}
}

// testVecF64ToUint32 properly handles conversion of float64s read from the JSON
// test data to unsigned 32-bit integers.  This is necessary because some of the
// test data uses -1 as a shortcut to mean max uint32 and direct conversion of a
// negative float to an unsigned int is implementation dependent and therefore
// doesn't result in the expected value on all platforms.  This function woks
// around that limitation by converting to a 32-bit signed integer first and
// then to a 32-bit unsigned integer which results in the expected behavior on
// all platforms.
func testVecF64ToUint32(f float64) uint32 {
	return uint32(int32(f)) //nolint:gosec // G115 -- intentional wraparound conversion matching reference test semantics
}

type txIOKey struct {
	id  string
	idx uint32
}

// Transaction-level consensus limits CheckTransactionCommon applies in the
// node's tx_valid/tx_invalid runner (test/transaction_tests.cpp RunTests,
// which validates as ProtocolEra::PreGenesis).
const (
	maxTxSizeConsensusBeforeGenesis = 1_000_000
	maxMoney                        = 21_000_000 * 100_000_000
	maxCoinbaseScriptSigSize        = 100
)

// isNullOutpoint mirrors COutPoint::IsNull.
func isNullOutpoint(in *transaction.TransactionInput) bool {
	return in.SourceTxOutIndex == ^uint32(0) && (in.SourceTXID == nil || in.SourceTXID.IsEqual(&chainhash.Hash{}))
}

// checkTransaction mirrors the node's context-free CheckCoinbase and
// CheckRegularTransaction (validation.cpp) for the pre-Genesis era the
// tx_valid/tx_invalid runner uses. The pre-Genesis sigop limit is not
// modelled: no vector reaches it.
func checkTransaction(tx *transaction.Transaction) error {
	if len(tx.Inputs) == 0 {
		return errors.New("bad-txns-vin-empty")
	}
	if len(tx.Outputs) == 0 {
		return errors.New("bad-txns-vout-empty")
	}
	if len(tx.Bytes()) > maxTxSizeConsensusBeforeGenesis {
		return errors.New("bad-txns-oversize")
	}
	var valueOut int64
	for _, out := range tx.Outputs {
		v := int64(out.Satoshis) //nolint:gosec // G115 -- nValue is a signed int64 on the wire
		if v < 0 {
			return errors.New("bad-txns-vout-negative")
		}
		if v > maxMoney {
			return errors.New("bad-txns-vout-toolarge")
		}
		valueOut += v
		if valueOut > maxMoney {
			return errors.New("bad-txns-txouttotal-toolarge")
		}
	}
	if len(tx.Inputs) == 1 && isNullOutpoint(tx.Inputs[0]) {
		if n := len(*tx.Inputs[0].UnlockingScript); n < 2 || n > maxCoinbaseScriptSigSize {
			return errors.New("bad-cb-length")
		}
		return nil
	}
	seen := make(map[txIOKey]struct{}, len(tx.Inputs))
	for _, in := range tx.Inputs {
		if isNullOutpoint(in) {
			return errors.New("bad-txns-prevout-null")
		}
		k := txIOKey{id: in.SourceTXID.String(), idx: in.SourceTxOutIndex}
		if _, dup := seen[k]; dup {
			return errors.New("bad-txns-inputs-duplicate")
		}
		seen[k] = struct{}{}
	}
	return nil
}

// runTxTests mirrors RunTests in bitcoin-sv's test/transaction_tests.cpp.
// Each vector is either ["comment"] or
//
//	[[[prevout hash, prevout index, prevout scriptPubKey, amount?]...], serializedTransaction, verifyFlags|[verifyFlags...]]
//
// A vector is valid when it passes the context-free transaction checks and
// every input verifies under every listed flag set; an invalid vector must
// fail the transaction checks or fail some input under each flag set.
func runTxTests(t *testing.T, path string, shouldBeValid bool) {
	t.Helper()
	file, err := os.ReadFile(path) //nolint:gosec // G304 -- test reads a fixed local testdata file
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	var tests [][]any
	if err = json.Unmarshal(file, &tests); err != nil {
		t.Fatalf("%s: couldn't Unmarshal: %v", path, err)
	}

	for i, test := range tests {
		inputs, ok := test[0].([]any)
		if !ok {
			continue
		}
		if len(test) != 3 {
			t.Errorf("bad test (bad length) %d: %v", i, test)
			continue
		}
		serializedhex, ok := test[1].(string)
		if !ok {
			t.Errorf("bad test (arg 2 not string) %d: %v", i, test)
			continue
		}

		flagStrs, flagSets, err := parseTxTestFlags(test[2])
		if err != nil {
			t.Errorf("bad test %d: %v: %v", i, err, test)
			continue
		}

		prevOuts, err := parseTxTestPrevOuts(inputs)
		if err != nil {
			t.Errorf("bad test %d: %v: %v", i, err, test)
			continue
		}

		tx, err := transaction.NewTransactionFromHex(serializedhex)
		if err == nil {
			err = checkTransaction(tx)
		}
		if err != nil {
			// The node deserializes the two segwit-marker vectors in
			// tx_invalid.json as transactions with no inputs, which
			// CheckTransactionCommon rejects; the SDK refuses to parse them.
			if shouldBeValid {
				t.Errorf("test %d: %v: %v", i, err, test)
			}
			continue
		}

		for j, flags := range flagSets {
			valid := true
			k := 0
			for ; k < len(tx.Inputs) && valid; k++ {
				txin := tx.Inputs[k]
				prevOut, ok := prevOuts[txIOKey{id: txin.SourceTXID.String(), idx: txin.SourceTxOutIndex}]
				if !ok {
					t.Errorf("bad test (missing %dth input) %d: %v", k, i, test)
					break
				}
				txin.SetSourceTxOutput(prevOut)
				valid = NewEngine().Execute(WithTx(tx, k, prevOut), WithFlags(flags)) == nil
			}
			if valid != shouldBeValid {
				t.Errorf("test %d: flags %q: valid=%v on input %d, want %v: %v", i, flagStrs[j], valid, k-1, shouldBeValid, test)
			}
		}
	}
}

// parseTxTestFlags parses a tx_valid/tx_invalid vector's verifyFlags field:
// one flag string or a non-empty array of them.
func parseTxTestFlags(field any) ([]string, []scriptflag.Flag, error) {
	var strs []string
	switch f := field.(type) {
	case string:
		strs = []string{f}
	case []any:
		for _, v := range f {
			s, ok := v.(string)
			if !ok {
				return nil, nil, errors.New("verifyFlags array holds a non-string")
			}
			strs = append(strs, s)
		}
	}
	if len(strs) == 0 {
		return nil, nil, errors.New("verifyFlags is not a string or a non-empty string array")
	}
	flags := make([]scriptflag.Flag, len(strs))
	for j, str := range strs {
		var err error
		if flags[j], err = parseScriptFlags(str); err != nil {
			return nil, nil, err
		}
	}
	return strs, flags, nil
}

// parseTxTestPrevOuts parses a tx_valid/tx_invalid vector's prevout list.
func parseTxTestPrevOuts(inputs []any) (map[txIOKey]*transaction.TransactionOutput, error) {
	prevOuts := make(map[txIOKey]*transaction.TransactionOutput, len(inputs))
	for j, iinput := range inputs {
		input, ok := iinput.([]any)
		if !ok || len(input) < 3 || len(input) > 4 {
			return nil, fmt.Errorf("%dth input is not a 3 or 4 element array", j)
		}
		previoustx, ok := input[0].(string)
		if !ok {
			return nil, fmt.Errorf("%dth input hash not string", j)
		}
		idxf, ok := input[1].(float64)
		if !ok {
			return nil, fmt.Errorf("%dth input idx not number", j)
		}
		oscript, ok := input[2].(string)
		if !ok {
			return nil, fmt.Errorf("%dth input script not string", j)
		}
		lockingScript, err := parseShortForm(oscript)
		if err != nil {
			return nil, fmt.Errorf("%dth input script doesn't parse: %w", j, err)
		}
		var inputValue float64
		if len(input) == 4 {
			if inputValue, ok = input[3].(float64); !ok {
				return nil, fmt.Errorf("%dth input value not int", j)
			}
		}
		prevOuts[txIOKey{id: previoustx, idx: testVecF64ToUint32(idxf)}] = &transaction.TransactionOutput{
			Satoshis:      uint64(inputValue),
			LockingScript: lockingScript,
		}
	}
	return prevOuts, nil
}

// TestTxInvalidTests ensures all of the tests in tx_invalid.json fail as
// expected.
func TestTxInvalidTests(t *testing.T) {
	runTxTests(t, "data/tx_invalid.json", false)
}

// TestTxValidTests ensures all of the tests in tx_valid.json pass as expected.
func TestTxValidTests(t *testing.T) {
	runTxTests(t, "data/tx_valid.json", true)
}
