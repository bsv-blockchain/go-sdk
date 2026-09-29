package interpreter

// Regression tests for GHSA-rh54-8fpg-8wwf, core execution state: one
// end-of-script path for running off the end of a script and for a top-level
// OP_RETURN, the OP_CODESEPARATOR scriptCode start, lazy failure of
// undecodable instructions and run-time-only top-level OP_RETURN, node's
// legacy SerializeScriptCode and the null signature checker used without a
// transaction. Every entry of coreOracleCases is a reproducer verified
// against bitcoin-sv (GoBDK): its per-word verdict is the real bitcoin-sv
// node's (bitcoin-sv 879fc8b42), which this interpreter matches. Helper names
// use the "core" prefix.

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/errs"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// coreNodeWordToFlags maps a node script-flag word to scriptflag.Flag bits.
func coreNodeWordToFlags(word uint32) scriptflag.Flag {
	var f scriptflag.Flag
	for bit, flag := range map[uint32]scriptflag.Flag{
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
	} {
		if word&bit != 0 {
			f |= flag
		}
	}
	return f
}

// coreWordCase is one reproducer verified against bitcoin-sv (GoBDK): a
// spending transaction, the locking script of each spent output, and the
// node's verdict per flag word.
type coreWordCase struct {
	name    string
	txHex   string
	locks   []string
	perWord map[uint32]bool
}

func (c coreWordCase) run(t *testing.T) {
	t.Helper()

	tx, err := transaction.NewTransactionFromHex(c.txHex)
	require.NoError(t, err)

	prevs := make([]*transaction.TransactionOutput, len(tx.Inputs))
	for i := range tx.Inputs {
		lockBytes, hexErr := hex.DecodeString(c.locks[i])
		require.NoError(t, hexErr)
		prevs[i] = &transaction.TransactionOutput{LockingScript: script.NewFromBytes(lockBytes), Satoshis: 1000}
	}

	for word, wantValid := range c.perWord {
		t.Run(fmt.Sprintf("word=0x%06x", word), func(t *testing.T) {
			var gotErr error
			require.NotPanics(t, func() {
				for i := range tx.Inputs {
					gotErr = NewEngine().Execute(WithTx(tx, i, prevs[i]), WithFlags(coreNodeWordToFlags(word)))
					if gotErr != nil {
						break
					}
				}
			})
			if wantValid {
				require.NoError(t, gotErr, "%s: node accepts under word 0x%06x", c.name, word)
			} else {
				require.Error(t, gotErr, "%s: node rejects under word 0x%06x", c.name, word)
			}
		})
	}
}

// TestGHSACoreOracleCases runs the reproducers verified against bitcoin-sv
// (GoBDK) for the end-of-script, OP_CODESEPARATOR, lazy-parse and
// SerializeScriptCode fixes (GHSA-rh54-8fpg-8wwf).
func TestGHSACoreOracleCases(t *testing.T) {
	t.Parallel()

	for _, c := range coreOracleCases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			c.run(t)
		})
	}
}

var coreOracleCases = []coreWordCase{
	{
		// scriptSig OP_1 OP_TOALTSTACK OP_RETURN, lock OP_FROMALTSTACK.
		// A top-level OP_RETURN ends the scriptSig's EvalScript; its alt stack
		// must not survive into the locking script.
		name:  "altstack survives scriptSig top-level OP_RETURN, v2 block word",
		txHex: "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000003516b6affffffff010100000000000000015100000000",
		locks: []string{"6c"},
		perWord: map[uint32]bool{
			0x3D462F: false,
			0x3D460F: false,
		},
	},
	{
		// Same, v1 under a word without SIGPUSHONLY.
		name:  "altstack survives scriptSig top-level OP_RETURN, v1 no-SIGPUSHONLY word",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000003516b6affffffff010100000000000000015100000000",
		locks: []string{"6c"},
		perWord: map[uint32]bool{
			0x3D460F: false,
		},
	},
	{
		// scriptSig <sig> OP_CODESEPARATOR OP_RETURN, P2PK lock: the codesep
		// position must not leak into the lock, whose scriptCode is the whole
		// lock.
		name:  "scriptSig <sig> OP_CODESEPARATOR OP_RETURN then P2PK lock, v1",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004b483045022100a8dda1186682dd3b52f5f212f9d956d7bcf0fb566f98b4303fba96743ec347600220627eedb3d63f316b62afec209f4b16792102d3ffd292f870a2c9cd8ec06c8c9c41ab6affffffff010100000000000000015100000000",
		locks: []string{"210265666e237a1523e156fddf24b8335f658f90e21330775a679b33b65fbaa38e38ac"},
		perWord: map[uint32]bool{
			0x3D460F: true,
		},
	},
	{
		// Same, v2.
		name:  "scriptSig <sig> OP_CODESEPARATOR OP_RETURN then P2PK lock, v2",
		txHex: "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004b483045022100f999b9d9506c3c8a256491b9099dd132b31f0dfe864aa17e95666271fb35972102200ddfae31f193f49fa32a0a35f76bfd0ec2e76655185992f41ba88f30315f4a0441ab6affffffff010100000000000000015100000000",
		locks: []string{"210265666e237a1523e156fddf24b8335f658f90e21330775a679b33b65fbaa38e38ac"},
		perWord: map[uint32]bool{
			0x3D462F: true,
			0x3D460F: true,
		},
	},
	{
		// The leaked codesep index is past the end of the (shorter) lock -- the
		// unpatched interpreter panicked slicing the scriptCode.
		name:  "codesep leak past lock end, v2",
		txHex: "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004f483045022100daf431a9d02ba28d9d06328e57342b4b4431ba2ca8264564c14c9989d256366002204d2f9ef69a5a449303bd14f6b065078cdc2e46223b32441c73d427d53c3ceac3415175ababab6affffffff010100000000000000015100000000",
		locks: []string{"2102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494ac"},
		perWord: map[uint32]bool{
			0x3D462F: true,
		},
	},
	{
		// Same, v1 under a word without SIGPUSHONLY.
		name:  "codesep leak past lock end, v1",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004e47304402206bed61eb31166e4c51c1ee029d1e7e757535c507ca852b8b4690656ed952ec3802202e55ac5b14cb8afeae0494372be9389e9a1a22dc0e8af08b99d10bc08d6a15c8415175ababab6affffffff010100000000000000015100000000",
		locks: []string{"2102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494ac"},
		perWord: map[uint32]bool{
			0x3D460F: true,
		},
	},
	{
		// An empty locking script after a scriptSig top-level OP_RETURN is
		// skipped like any empty script.
		name:  "EMPTY locking script, scriptSig OP_1 OP_RETURN (top-level early return), v2",
		txHex: "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000002516affffffff010100000000000000015100000000",
		locks: []string{""},
		perWord: map[uint32]bool{
			0x3D462F: true,
			0x3D460F: true,
		},
	},
	{
		// Control: empty locking script, no OP_RETURN.
		name:  "control: EMPTY locking script, scriptSig OP_1, v2",
		txHex: "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000000151ffffffff010100000000000000015100000000",
		locks: []string{""},
		perWord: map[uint32]bool{
			0x3D462F: true,
		},
	},
	{
		// As the first empty-lock case, v1.
		name:  "EMPTY locking script, scriptSig OP_1 OP_RETURN, v1, no-SIGPUSHONLY word",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000002516affffffff010100000000000000015100000000",
		locks: []string{""},
		perWord: map[uint32]bool{
			0x3D460F: true,
		},
	},
	{
		// An executed OP_CODESEPARATOR at index 0 moves the scriptCode start
		// past it: FORKID sig over <pk> CHECKSIG is valid.
		name:  "lock OP_CODESEPARATOR <pk> CHECKSIG, FORKID sig over node scriptCode (<pk> CHECKSIG)",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483045022100a8dda1186682dd3b52f5f212f9d956d7bcf0fb566f98b4303fba96743ec347600220627eedb3d63f316b62afec209f4b16792102d3ffd292f870a2c9cd8ec06c8c9c41ffffffff010100000000000000015100000000",
		locks: []string{"ab210265666e237a1523e156fddf24b8335f658f90e21330775a679b33b65fbaa38e38ac"},
		perWord: map[uint32]bool{
			0x3D462F: true,
			0x3D47FF: true,
		},
	},
	{
		// A sig over the whole lock (incl. the codesep) is not.
		name:  "same lock, FORKID sig over SDK scriptCode (incl. leading OP_CODESEPARATOR)",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000048473044022069e1262dd2fbbee488ec256a8085442b6851f4c05bdef354fe155ac75acb09d90220743b074d9eee3d1d7065129cc1c911c80f61e924752d5bfc1a2eab88f47d0e2541ffffffff010100000000000000015100000000",
		locks: []string{"ab210265666e237a1523e156fddf24b8335f658f90e21330775a679b33b65fbaa38e38ac"},
		perWord: map[uint32]bool{
			0x3D462F: false,
		},
	},
	{
		// As above, v2 (NULLFAIL exempt, EVAL_FALSE).
		name:  "same lock, FORKID sig over SDK scriptCode, v2 (NULLFAIL exempt -> EvalFalse)",
		txHex: "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483045022100dbbbfc6c532b3ed59df62da8d656cb33c618b16b867efcc93b32032f0c3bc8d9022020d933b2e7bf79c892e28f141dd2da27ac6f2be5119cfbd1ee11d50b2863e0a741ffffffff010100000000000000015100000000",
		locks: []string{"ab210265666e237a1523e156fddf24b8335f658f90e21330775a679b33b65fbaa38e38ac"},
		perWord: map[uint32]bool{
			0x3D462F: false,
		},
	},
	{
		// Control: legacy sig, pre-UAHF word.
		name:  "control: same lock, legacy sig (pre-UAHF word) over <pk> CHECKSIG",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483045022100e9afd3d0d3aa3afe685df587d15e50655f13e6f2d9edf367733ae24e17defe200220764c1004947cc3303953b34c040bc6c233c69f325f4948d4b0525737d5579f5501ffffffff010100000000000000015100000000",
		locks: []string{"ab210265666e237a1523e156fddf24b8335f658f90e21330775a679b33b65fbaa38e38ac"},
		perWord: map[uint32]bool{
			0x000605: true,
		},
	},
	{
		// Control: trailing codesep after CHECKSIG.
		name:  "control: lock <pk> CHECKSIG OP_CODESEPARATOR, FORKID sig over whole lock",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004847304402200db4a965f1c9d41a8cb5fe616c588991796a0cd07ba35c3070c5a050e86ac1c002204e2bcfd7cd6590d925476d0c278941b1978ebfdf31b31c6e68858ab23516048041ffffffff010100000000000000015100000000",
		locks: []string{"210265666e237a1523e156fddf24b8335f658f90e21330775a679b33b65fbaa38e38acab"},
		perWord: map[uint32]bool{
			0x3D462F: true,
		},
	},
	{
		// On a post-Genesis pre-Chronicle coin the unexecuted OP_VERIF is a
		// NOP, so the OP_RETURN is top-level at run time and the truncated
		// push after it is never read.
		name:  "lock OP_1 OP_0 OP_IF OP_VERIF OP_ENDIF OP_RETURN 0x4c, post-Genesis pre-Chronicle coin",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000000ffffffff010100000000000000015100000000",
		locks: []string{"51006365686a4c"},
		perWord: map[uint32]bool{
			0x1D462F: true,
			0x1D47FF: true,
		},
	},
	{
		// Same shape in the scriptSig.
		name:  "same shape in scriptSig, lock OP_1, v2",
		txHex: "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000000751006365686a4cffffffff010100000000000000015100000000",
		locks: []string{"51"},
		perWord: map[uint32]bool{
			0x1D462F: true,
		},
	},
	{
		// Control: truncated push after a top-level OP_RETURN.
		name:  "control: lock OP_1 OP_RETURN 0x4c (truncated push after top-level OP_RETURN)",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000000ffffffff010100000000000000015100000000",
		locks: []string{"516a4c"},
		perWord: map[uint32]bool{
			0x3D462F: true,
			0x3D47FF: true,
		},
	},
	{
		// Control: nested then top-level OP_RETURN then junk.
		name:  "control: nested OP_RETURN then top-level OP_RETURN then junk",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000000ffffffff010100000000000000015100000000",
		locks: []string{"5151636a686a4c"},
		perWord: map[uint32]bool{
			0x3D462F: true,
		},
	},
	{
		// Post-Chronicle coin: OP_VERIF is a real conditional, the OP_RETURN
		// is nested and the truncated push is reached.
		name:  "control: post-Chronicle coin, lock OP_1 OP_0 OP_IF OP_VERIF OP_ENDIF OP_RETURN 0x4c (OP_VERIF is a real conditional)",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000000ffffffff010100000000000000015100000000",
		locks: []string{"51006365686a4c"},
		perWord: map[uint32]bool{
			0x3D462F: false,
		},
	},
	{
		// Legacy sig over node's SerializeScriptCode of a lock ending in
		// OP_RETURN + lone 0x4c (synthetic word 0x080605).
		name:  "legacy sig over node's serialised scriptCode, lock <pk> CHECKSIG OP_RETURN lone 0x4c (synthetic word 0x80605)",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000484730440220619eaba5f3cdaa5be40c0a942593317dea96870a6dfa7c1297b24abc6ff431e502204407db082673d5eacb6f357ab00b8fe50326e84154dc0aea9544fb8b3398903c01ffffffff010100000000000000015100000000",
		locks: []string{"210265666e237a1523e156fddf24b8335f658f90e21330775a679b33b65fbaa38e38ac6a4c"},
		perWord: map[uint32]bool{
			0x080605: true,
		},
	},
	{
		// Tail 4c 05 01 -- node writes the bytes up to the length byte only,
		// under the full-length prefix.
		name:  "legacy sig over node's serialised scriptCode, lock <pk> CHECKSIG OP_RETURN 4c 05 01 (length byte present, node drops last byte from serialised bytes) (synthetic word 0x80605)",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004847304402201ccebdb91c61e5fbcb3501aee48b5f95bae0d830e92c0c07ce136447c85ae4e802205dc04a20d9084477d8297e42152c1ddaeba463f85f58518bf5f904664eadd9a601ffffffff010100000000000000015100000000",
		locks: []string{"210265666e237a1523e156fddf24b8335f658f90e21330775a679b33b65fbaa38e38ac6a4c0501"},
		perWord: map[uint32]bool{
			0x080605: true,
		},
	},
	{
		// Control: FORKID (BIP143) sig over the raw malformed tail.
		name:  "control: FORKID sig over lock <pk> CHECKSIG OP_RETURN 4c 05 01 (raw tail in BIP143 scriptCode)",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000049483045022100a84493f7eedd2d34eba2787a96166e3d0ea8daa8b974076ee04c2995ba1081ed02206cabc14d9c5f3929e73352f6389937cea093c4ea4c23275bf166ab4e675ec5cf41ffffffff010100000000000000015100000000",
		locks: []string{"210265666e237a1523e156fddf24b8335f658f90e21330775a679b33b65fbaa38e38ac6a4c0501"},
		perWord: map[uint32]bool{
			0x3D462F: true,
		},
	},
	{
		// Real post-Chronicle SIGHASH_CHRONICLE (legacy digest) sig, lone 0x4c.
		name:  "SerializeScriptCode, real sig: ht 0x61 over <pk> CHECKSIG OP_RETURN lone 4c, v1",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004847304402200bb6ee41aace77dbd9d8f8b5aa43d92f1594016561e8778a99a863eba95b559a02204d03666c9d07294ea6607db92ba608d23fb5648ea1ad83843e2e71fa84ea6b3661ffffffff02010000000000000001510100000000000000015100000000",
		locks: []string{"2102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494ac6a4c"},
		perWord: map[uint32]bool{
			0x3D462F: true,
			0x3D47FF: true,
		},
	},
	{
		// Real sig: tail 4c 05 01, v2.
		name:  "SerializeScriptCode, real sig: ht 0x61 over <pk> CHECKSIG OP_RETURN 4c 05 01, v2",
		txHex: "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004847304402207d56f419b1e3f8a283851e8430fa157961ae58ab1b2069683b530d50ffe71a9302203389279c95f1e401238364f47bcec68a1455713bdcb76378cdc4e6cf96a7c1f561ffffffff02010000000000000001510100000000000000015100000000",
		locks: []string{"2102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494ac6a4c0501"},
		perWord: map[uint32]bool{
			0x3D462F: true,
			0x3D47FF: true,
		},
	},
	{
		// Real sig: ALL|ANYONECANPAY|FORKID|CHRONICLE, tail 4d ff.
		name:  "SerializeScriptCode, real sig: ht 0xe1 over <pk> CHECKSIG OP_RETURN 4d ff, v1",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000494830450221008d1605213494377464c87c44497ba400b24f9bee7e136fe2c41742237c48b1a9022077f7331cfa94653631144c13fc6422996d41bae9c2ae5ce971d00c2f8efc3ceee1ffffffff02010000000000000001510100000000000000015100000000",
		locks: []string{"2102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494ac6a4dff"},
		perWord: map[uint32]bool{
			0x3D462F: true,
			0x3D47FF: true,
		},
	},
	{
		// Real sig: NONE|FORKID|CHRONICLE, OP_CODESEPARATOR inside the
		// unexecuted tail is still stripped (and not counted twice) by the
		// serializer.
		name:  "SerializeScriptCode, real sig: ht 0x62 over <pk> CHECKSIG OP_RETURN ab 4c 05 01 (codesep before tail), v2",
		txHex: "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000004847304402202bbdd0d481f1ed449db53ad22f0f0b2c179cca5866ab317eb0649934ba5e637402203a1ea0145a4f2582fc17f10d334cf7507a0f4169a17eed8c7c2375cabfe77c3e62ffffffff02010000000000000001510100000000000000015100000000",
		locks: []string{"2102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494ac6aab4c0501"},
		perWord: map[uint32]bool{
			0x3D462F: true,
			0x3D47FF: true,
		},
	},
	{
		// Real sig: SINGLE|FORKID|CHRONICLE, push + codesep + truncated push.
		name:  "SerializeScriptCode, real sig: ht 0x63 over <pk> CHECKSIG OP_RETURN 00 ab 4c (codesep, push, tail), v1",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000048473044022059b94c739378d09a7e5715e37b6dcab867bf066ce1a86f5afe75db6a3e424f5002205b50ab8afd565fc55e947e6194bb7b46626e7e1c854d369c62e6ba202916fa8663ffffffff02010000000000000001510100000000000000015100000000",
		locks: []string{"2102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494ac6a00ab4c"},
		perWord: map[uint32]bool{
			0x3D462F: true,
			0x3D47FF: true,
		},
	},
	{
		// Real sig: truncated PUSHDATA4 with codeseps in its (missing) data.
		name:  "SerializeScriptCode, real sig: ht 0x61 over <pk> CHECKSIG OP_RETURN 4e 09 00 00 00 ab ab, v2",
		txHex: "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000048473044022067fb828a26dc40f7a3270770f4049f42a286c4b4ac8f3cf81e7a05e51e32d6de0220597333401296fdd688c245593798a1f80e18c7ea976b94e306db594955949b7e61ffffffff02010000000000000001510100000000000000015100000000",
		locks: []string{"2102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494ac6a4e09000000abab"},
		perWord: map[uint32]bool{
			0x3D462F: true,
			0x3D47FF: true,
		},
	},
	{
		// Real sig: truncated direct push.
		name:  "SerializeScriptCode, real sig: ht 0x61 over <pk> CHECKSIG OP_RETURN 05 aa bb, v1",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000048473044022009f4b783b8ee4003d4c5b2502df608d858c8a2cec393aced702017b86f685463022025caa84ff1fa647d3bf30978dceb73d9c483b8c4627342f23f440df3d86bb63c61ffffffff02010000000000000001510100000000000000015100000000",
		locks: []string{"2102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494ac6a05aabb"},
		perWord: map[uint32]bool{
			0x3D462F: true,
			0x3D47FF: true,
		},
	},
	{
		// Node's FindAndDelete scans past a top-level OP_RETURN: a legacy sig
		// whose push reappears after the scriptSig's OP_RETURN is removed from the
		// scriptCode twice (synthetic word 0x080605, the only way to combine
		// FindAndDelete with a successful top-level OP_RETURN).
		name:  "sig pushed again after scriptSig top-level OP_RETURN (FindAndDelete past OP_RETURN)",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000b6483045022100eed98a0e87174243686b24eb936c0fec2a24f7f6358dce4be39aad5ab2ca27fb022030b2e2fdfe16f0e1fde590b9d5067d7b085a058efb1e520ac65997aed25b70b5012102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494ac6a483045022100eed98a0e87174243686b24eb936c0fec2a24f7f6358dce4be39aad5ab2ca27fb022030b2e2fdfe16f0e1fde590b9d5067d7b085a058efb1e520ac65997aed25b70b501ffffffff010100000000000000015100000000",
		locks: []string{"61"},
		perWord: map[uint32]bool{
			0x080605: true,
		},
	},
	{
		// Same, with a malformed tail after the repeated push.
		name:  "sig pushed again after scriptSig top-level OP_RETURN (FindAndDelete past OP_RETURN) + malformed tail",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000b7483045022100b687169239ae00add6ebf3d2a65bd724a602fa4e8c25361c18e65075b9ff7a240220739a62204b0f36bb9cd69a02057392177f786442f9a79d33df47ebea1f719a84012102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494ac6a483045022100b687169239ae00add6ebf3d2a65bd724a602fa4e8c25361c18e65075b9ff7a240220739a62204b0f36bb9cd69a02057392177f786442f9a79d33df47ebea1f719a84014cffffffff010100000000000000015100000000",
		locks: []string{"61"},
		perWord: map[uint32]bool{
			0x080605: true,
		},
	},
	{
		// Randomized batch (seed 24 #49): VERIF-as-NOP before a top-level OP_RETURN
		// in the scriptSig, malformed tail after it.
		name:  "rnd s24 #49 verif-nop-return+mal-ss v2",
		txHex: "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000000a5151006365686a6a4ca4ffffffff010100000000000000015100000000",
		locks: []string{"5163ab67ab68"},
		perWord: map[uint32]bool{
			0x1D462F: true,
		},
	},
	{
		// Randomized batch (seed 25 #542): same in the lock, v1.
		name:  "rnd s25 #542 verif-nop-return+mal-lock v1",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000000ffffffff02010000000000000001510100000000000000015100000000",
		locks: []string{"747551006366686a6a4d39"},
		perWord: map[uint32]bool{
			0x1D462F: true,
		},
	},
	{
		// Randomized batch (seed 24 #141): alt stack leak across a scriptSig OP_RETURN.
		name:  "rnd s24 #141 return-leak v2",
		txHex: "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000005ab516b516affffffff010100000000000000015100000000",
		locks: []string{"6c"},
		perWord: map[uint32]bool{
			0x3D462F: false,
			0x3D47FF: false,
		},
	},
	{
		// Randomized batch (seed 25 #250): scriptSig OP_RETURN with a malformed tail.
		name:  "rnd s25 #250 return-leak+mal-ss v2",
		txHex: "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000000b0063656868516b516a4c2affffffff010100000000000000015100000000",
		locks: []string{""},
		perWord: map[uint32]bool{
			0x3D462F: true,
			0x3D47FF: true,
		},
	},
	{
		// Randomized batch (seed 23 #50): codesep at index 0, post-Genesis coin.
		name:  "rnd s23 #50 codesep-0 v2",
		txHex: "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000047463043021f58265417b6a1753d777cf9e5e431bb2bc8c5f0b6b1f74c6ac2051014b68bb6022077ebe8c4f891a3733014d003be04ec37a815be9cfe816fef47300bb8e11577dec3ffffffff010100000000000000015100000000",
		locks: []string{"ab006366682102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494ac"},
		perWord: map[uint32]bool{
			0x1D462F: true,
		},
	},
	{
		// Randomized batch (seed 23 #64): codesep at index 0, pre-Genesis coin.
		name:  "rnd s23 #64 codesep-0 v2",
		txHex: "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000496147304402205c93b84b9297637a8be5d7e7879b6c7516fb0c361b918a72a1b669da344fe66e0220205e6205b9ec9808e3a799a007d751d3171f1e313abd978b2064d1cbf37d93cb41ffffffff010100000000000000015100000000",
		locks: []string{"ab02b8777521025de9f066f533e30e319a3b6689641957a98f844a928d7290c62b6eb803ff94aaac"},
		perWord: map[uint32]bool{
			0x15462F: true,
		},
	},
	{
		// Randomized batch (seed 23 #450): CHECKSIG in the scriptSig after a codesep;
		// its Chronicle scriptCode appends the whole lock, codesep included.
		name:  "rnd s23 #450 scriptsig-checksig v2",
		txHex: "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000006d483045022100849add6bc11bd25224810039017368374331561bf11c0e2d04c965485d20df72022027432b2cc05258dd46ee0da639f970fb7642f8cb50a64a3665135ce6b3953e5dc121025de9f066f533e30e319a3b6689641957a98f844a928d7290c62b6eb803ff94aaac51ffffffff010100000000000000015100000000",
		locks: []string{"61ab"},
		perWord: map[uint32]bool{
			0x3D462F: true,
			0x3D47FF: true,
		},
	},
	{
		// Randomized batch (seed 23 #456): same with a malformed scriptSig tail after
		// a top-level OP_RETURN.
		name:  "rnd s23 #456 scriptsig-checksig+mal-ss v2",
		txHex: "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000072483045022100d9b49ccef5afb6b7c85d95422d7412dffbac14b7cb73ab22925576dbae11333102206547d81d7ef21b457da98f0342147bff3ef5d20722165544d8d636423a168c0be32102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a49461abac516a4d8bffffffff010100000000000000015100000000",
		locks: []string{""},
		perWord: map[uint32]bool{
			0x3D462F: true,
			0x3D47FF: true,
		},
	},
	{
		// Randomized batch (seed 24 #238): legacy sig in the scriptSig, codeseps in
		// the lock (synthetic word 0x080605).
		name:  "rnd s24 #238 scriptsig-checksig v1",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000006d473044022026ae245f7b6bbcab62269af40f345e583b540bb3fe8e03688a0ae5e2e26f299a0220356d53053964fc546625199975717af614c076fa3f3845ab4ef3a2b95b547a380221025de9f066f533e30e319a3b6689641957a98f844a928d7290c62b6eb803ff94aaabad51ffffffff010100000000000000015100000000",
		locks: []string{"abab00636668"},
		perWord: map[uint32]bool{
			0x080605: true,
		},
	},
	// A Chronicle CHECKSIG in the scriptSig signs scriptSig + scriptPubKey as
	// one script. When the scriptSig ends in an undecodable push after a
	// top-level OP_RETURN, that push swallows lock bytes in the joined script,
	// so FindAndDelete and the legacy OP_CODESEPARATOR removal must decode the
	// joined bytes, not the two scripts separately. Legacy signatures, i.e.
	// Chronicle words without SIGHASH_FORKID (synthetic words 0x3C0605 and
	// 0x3C0607).
	{
		// The lock's OP_CODESEPARATOR is push data of 4c 01 in the joined script.
		name:  "concat: tail 4c 01 swallows the lock's OP_CODESEPARATOR, v2",
		txHex: "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000006f473044022014dff71b92310224aa32048802679fcd7cb5da8f056f8714fac5aca6fa455e6b02205a4bb20399a358988763a15cd4e0277a2ea72bd209d5318e68047e5ba078e89d012102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494ad516a4c01ffffffff010100000000000000015100000000",
		locks: []string{"ab51"},
		perWord: map[uint32]bool{
			0x3C0605: true,
			0x3C0607: true,
		},
	},
	{
		// The joined script is still undecodable at 4c 05: nothing after it is
		// decoded, so the lock's OP_CODESEPARATOR is neither removed nor counted.
		name:  "concat: tail 4c 05 stays undecodable over lock ab 51, v1",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000006f47304402200ddfe872f4a9e9a339937c67eb2f35cfe5a6b13ebeb6d1aa87914b63fe22f20302204dbe6edd52542879c39cd1a90babd03662cfd29578a2c32cf41b026b969bdaee012102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494ad516a4c05ffffffff010100000000000000015100000000",
		locks: []string{"ab51"},
		perWord: map[uint32]bool{
			0x3C0605: true,
			0x3C0607: true,
		},
	},
	{
		name:  "concat: direct push 02 swallows both lock codeseps, v2",
		txHex: "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000006f483045022100a45c06a35ed9240a9b921e6500183cd2bec4c8a5db1efbf697a4b019ea97a484022057be203dc8349fa4babac9e5c118d2709a270d3f63d64657f803690a85e92cff012102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494ad516a02ffffffff010100000000000000015100000000",
		locks: []string{"abab51"},
		perWord: map[uint32]bool{
			0x3C0605: true,
			0x3C0607: true,
		},
	},
	{
		// CHECKMULTISIGVERIFY; 4d 01 00 swallows the first codesep only.
		name:  "concat: CHECKMULTISIGVERIFY, tail 4d 01 00 swallows one of two lock codeseps, v2",
		txHex: "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0000000007300473044022070a5490eb267cb9cb189ee2aaf119b4e8955bf12aa52d216bd16a887be0a4d64022020906b955f011478e6f78d5d874d65e9e8ec80186d235e1215390deea620bca401512102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a49451af516a4d0100ffffffff010100000000000000015100000000",
		locks: []string{"abab51"},
		perWord: map[uint32]bool{
			0x3C0605: true,
			0x3C0607: true,
		},
	},
	{
		// The lock repeats the signature's push, which the joined script swallows
		// into the scriptSig's 4c 49 push: node keeps it in the scriptCode, so a
		// signature over the scriptCode without it is invalid.
		name:  "concat: lock's copy of the sig push swallowed by tail 4c 49, sig over separate-parse scriptCode, v1",
		txHex: "0100000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000070483045022100d086c62ee03e99778251b7f365e4d148081eff83ba18ed67eefed2945091df4702204689c7aa1b88d93f40db4e08b92c78b8214db98c3dbac2a3a0338f22cd2f6981012102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494ad516a4c49ffffffff010100000000000000015100000000",
		locks: []string{"483045022100d086c62ee03e99778251b7f365e4d148081eff83ba18ed67eefed2945091df4702204689c7aa1b88d93f40db4e08b92c78b8214db98c3dbac2a3a0338f22cd2f6981017551"},
		perWord: map[uint32]bool{
			0x3C0605: false,
			0x3C0607: false,
		},
	},
	{
		name:  "concat: lock's copy of the sig push swallowed by tail 4c 49, sig over separate-parse scriptCode, v2",
		txHex: "0200000001c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000000704830450221009813c272e7d22d5c3cff1dc3653cda8f3274daf8c9d0ecea9539e5a73f63e4670220768dea430b263fefc1184bcc102777b318a81302beb4beacecb50ba02925aea4012102100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494ad516a4c49ffffffff010100000000000000015102000000",
		locks: []string{"4830450221009813c272e7d22d5c3cff1dc3653cda8f3274daf8c9d0ecea9539e5a73f63e4670220768dea430b263fefc1184bcc102777b318a81302beb4beacecb50ba02925aea4017551"},
		perWord: map[uint32]bool{
			0x3C0605: false,
			0x3C0607: false,
		},
	},
}

// coreScript decodes a hex script.
func coreScript(t *testing.T, h string) *script.Script {
	t.Helper()
	s, err := script.NewFromHex(h)
	require.NoError(t, err)
	return s
}

// TestGHSACoreNullChecker checks that, executed without a transaction
// (WithScripts), CHECKLOCKTIMEVERIFY/CHECKSEQUENCEVERIFY, OP_VER and
// OP_VERIF/OP_VERNOTIF behave like node's BaseSignatureChecker
// (interpreter.h:52-72): lock-time checks fail and the version is 0.
func TestGHSACoreNullChecker(t *testing.T) {
	t.Parallel()

	const (
		cltvLock        = "00b17551"           // OP_0 OP_CHECKLOCKTIMEVERIFY OP_DROP OP_1
		csvLock         = "00b27551"           // OP_0 OP_CHECKSEQUENCEVERIFY OP_DROP OP_1
		csvDisabledLock = "050000008000b27551" // <1<<31> OP_CHECKSEQUENCEVERIFY OP_DROP OP_1
	)
	tests := []struct {
		name    string
		lock    string
		flags   scriptflag.Flag
		wantErr errs.ErrorCode // errs.ErrOK: valid
	}{
		{"CLTV fails without a tx", cltvLock, scriptflag.VerifyCheckLockTimeVerify, errs.ErrUnsatisfiedLockTime},
		{"CSV fails without a tx", csvLock, scriptflag.VerifyCheckSequenceVerify, errs.ErrUnsatisfiedLockTime},
		{"CSV with the disable bit is a NOP", csvDisabledLock, scriptflag.VerifyCheckSequenceVerify, errs.ErrOK},
		{"CLTV without its flag is a NOP", cltvLock, 0, errs.ErrOK},
		{"CSV without its flag is a NOP", csvLock, 0, errs.ErrOK},
		{"CLTV after Genesis is a NOP", cltvLock, scriptflag.VerifyCheckLockTimeVerify | scriptflag.UTXOAfterGenesis, errs.ErrOK},
		// OP_VER <00000000> OP_EQUAL
		{"OP_VER pushes version 0", "620400000000" + "87", scriptflag.UTXOAfterGenesis | scriptflag.UTXOAfterChronicle, errs.ErrOK},
		// <00000000> OP_VERIF OP_1 OP_ELSE OP_0 OP_ENDIF
		{"OP_VERIF matches version 0", "0400000000" + "65516700" + "68", scriptflag.UTXOAfterGenesis | scriptflag.UTXOAfterChronicle, errs.ErrOK},
		// <01000000> OP_VERIF OP_1 OP_ELSE OP_0 OP_ENDIF
		{"OP_VERIF rejects version 1", "0401000000" + "65516700" + "68", scriptflag.UTXOAfterGenesis | scriptflag.UTXOAfterChronicle, errs.ErrEvalFalse},
		// <00000000> OP_VERNOTIF OP_0 OP_ELSE OP_1 OP_ENDIF
		{"OP_VERNOTIF matches version 0", "0400000000" + "66006751" + "68", scriptflag.UTXOAfterGenesis | scriptflag.UTXOAfterChronicle, errs.ErrOK},
		// A checksig opcode after a top-level OP_RETURN can never run.
		{"CHECKSIG after top-level OP_RETURN", "516aac", scriptflag.UTXOAfterGenesis, errs.ErrOK},
		{"CHECKSIG after nested OP_RETURN", "5151636a68ac", scriptflag.UTXOAfterGenesis, errs.ErrInvalidParams},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var err error
			require.NotPanics(t, func() {
				err = NewEngine().Execute(
					WithScripts(coreScript(t, tt.lock), coreScript(t, "51")),
					WithFlags(tt.flags),
				)
			})
			if tt.wantErr == errs.ErrOK {
				require.NoError(t, err)
				return
			}
			require.True(t, errs.IsErrorCode(err, tt.wantErr), "want %v, got %v", tt.wantErr, err)
		})
	}

	t.Run("WithTx without a previous output", func(t *testing.T) {
		t.Parallel()
		tx := transaction.NewTransaction()
		tx.AddInput(&transaction.TransactionInput{
			SourceTXID:      tx.TxID(),
			UnlockingScript: coreScript(t, "51"),
			SequenceNumber:  0xfffffffe,
		})
		var err error
		require.NotPanics(t, func() {
			err = NewEngine().Execute(
				WithTx(tx, 0, nil),
				WithScripts(coreScript(t, cltvLock), nil),
				WithFlags(scriptflag.VerifyCheckLockTimeVerify),
			)
		})
		require.NoError(t, err)
	})
}

// TestGHSACoreLazyParse checks that Parse decodes every instruction the way
// CScript::GetOp does and turns an undecodable tail into one malformed
// opcode that only fails once execution reaches it.
func TestGHSACoreLazyParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		script    string
		ops       int
		malformed string // hex of the undecodable tail, "" if none
	}{
		{"4c", 1, "4c"},
		{"4c05aa", 1, "4c05aa"},
		{"4d", 1, "4d"},
		{"4dff", 1, "4dff"},
		{"4d0200aa", 1, "4d0200aa"},
		{"4e010203", 1, "4e010203"},
		{"4e0500000001", 1, "4e0500000001"},
		{"05aabb", 1, "05aabb"},
		{"516a4c", 3, "4c"},
		{"51634c6851", 3, "4c6851"},
		{"6a0024dc", 3, "24dc"},
		{"6a4c0101", 2, ""},
		{"4c00", 1, ""},
		{"4d0000", 1, ""},
		{"4e00000000", 1, ""},
		{"", 0, ""},
	}
	parser := DefaultOpcodeParser{nodeExact: true}
	for _, tt := range tests {
		t.Run(tt.script, func(t *testing.T) {
			t.Parallel()
			s := coreScript(t, tt.script)
			pscr, err := parser.Parse(s)
			require.NoError(t, err)
			require.Len(t, pscr, tt.ops)
			for i, pop := range pscr {
				require.Equal(t, tt.malformed != "" && i == len(pscr)-1, pop.isMalformed(), "op %d", i)
			}
			if tt.malformed != "" {
				last := pscr[len(pscr)-1]
				require.Equal(t, tt.malformed, hex.EncodeToString(last.Data))
				require.Equal(t, script.OpINVALIDOPCODE, last.Value())
				require.False(t, pscr.IsPushOnly())
			}
			unparsed, err := parser.Unparse(pscr)
			require.NoError(t, err)
			require.Equal(t, []byte(*s), []byte(*unparsed))
		})
	}

	t.Run("round trip of random bytes", func(t *testing.T) {
		t.Parallel()
		r := rand.New(rand.NewSource(1)) //nolint:gosec // deterministic test data
		for i := 0; i < 2000; i++ {
			b := make([]byte, r.Intn(64))
			_, _ = r.Read(b)
			pscr, err := parser.Parse(script.NewFromBytes(b))
			require.NoError(t, err)
			for j, pop := range pscr {
				require.False(t, pop.isMalformed() && j != len(pscr)-1, "malformed opcode before the end of %x", b)
			}
			unparsed, err := parser.Unparse(pscr)
			require.NoError(t, err)
			require.True(t, bytes.Equal(b, *unparsed), "%x", b)
		}
	})

	t.Run("signature removal never touches the malformed tail", func(t *testing.T) {
		t.Parallel()
		// <aabb> followed by a 5-byte push with only 2 bytes: aa bb.
		pscr, err := parser.Parse(coreScript(t, "02aabb05aabb"))
		require.NoError(t, err)
		require.Len(t, pscr, 2)
		raw, err := parser.Unparse(pscr)
		require.NoError(t, err)
		keptBytes := removeOpcodeByData(*raw, []byte{0xaa, 0xbb})
		require.Equal(t, []byte{0x05, 0xaa, 0xbb}, keptBytes)
		kept, err := parser.Parse(script.NewFromBytes(keptBytes))
		require.NoError(t, err)
		require.Len(t, kept, 1)
		require.True(t, kept[0].isMalformed())
	})

	t.Run("checksig without tx is rejected before a top-level OP_RETURN only", func(t *testing.T) {
		t.Parallel()
		p := DefaultOpcodeParser{ErrorOnCheckSig: true, nodeExact: true}
		for h, wantErr := range map[string]bool{
			"ac":         true,
			"6aac":       false,
			"516a4cac":   false,
			"63006a68ac": true, // OP_RETURN nested in OP_IF
			"656a68ac":   true, // OP_VERIF counts as a conditional here
		} {
			_, err := p.Parse(coreScript(t, h))
			require.Equal(t, wantErr, errs.IsErrorCode(err, errs.ErrInvalidParams), h)
		}
	})

	t.Run("malformed tail fails when reached, even unexecuted", func(t *testing.T) {
		t.Parallel()
		for h, wantErr := range map[string]bool{
			"00634c6851": true,  // OP_0 OP_IF <malformed ...>
			"6a4c":       false, // top-level OP_RETURN first
			"51636a684c": true,  // nested OP_RETURN does not end the script
		} {
			err := NewEngine().Execute(
				WithScripts(coreScript(t, h), coreScript(t, "51")),
				WithAfterGenesis(),
			)
			if wantErr {
				require.True(t, errs.IsErrorCode(err, errs.ErrMalformedPush), "%s: %v", h, err)
			} else {
				require.NoError(t, err, h)
			}
		}
	})
}

// coreCodeSepRecorder records State.LastCodeSeparatorIdx before each opcode.
type coreCodeSepRecorder struct {
	nopDebugger

	start, idx []int
}

func (d *coreCodeSepRecorder) BeforeExecuteOpcode(s *State) {
	d.start = append(d.start, s.ScriptCodeStart)
	d.idx = append(d.idx, s.LastCodeSeparatorIdx)
}

// TestGHSACoreCodeSeparatorState covers State.ScriptCodeStart: 0 until an
// OP_CODESEPARATOR has executed, then one past its index (index 0 included),
// reset for the next script, including after a scriptSig top-level OP_RETURN.
// LastCodeSeparatorIdx keeps its historical meaning, 0 when none executed.
func TestGHSACoreCodeSeparatorState(t *testing.T) {
	t.Parallel()

	rec := &coreCodeSepRecorder{}
	// scriptSig: OP_1 OP_CODESEPARATOR OP_RETURN; lock: OP_CODESEPARATOR OP_NOP
	err := NewEngine().Execute(
		WithScripts(coreScript(t, "ab61"), coreScript(t, "51ab6a")),
		WithAfterGenesis(),
		WithDebugger(rec),
	)
	require.NoError(t, err)
	require.Equal(t, []int{0, 0, 2, 0, 1}, rec.start)
	require.Equal(t, []int{0, 0, 1, 0, 0}, rec.idx)
}

// TestGHSACoreSetState checks that SetState accepts a zero-value or legacy
// code-separator position, round-trips a separator at index 0, and re-derives
// the rules the flags decide rather than keeping the thread's own.
func TestGHSACoreSetState(t *testing.T) {
	t.Parallel()

	newThread := func(t *testing.T) *thread {
		t.Helper()
		th, err := createThread(&execOpts{
			lockingScript:   coreScript(t, "51"),
			unlockingScript: coreScript(t, "51"),
			epochSet:        true, // pre-Genesis, so re-deriving the flags visibly changes the era
		})
		require.NoError(t, err)
		return th
	}

	for _, tc := range []struct {
		name      string
		state     State
		wantStart int
	}{
		{"zero value", State{}, 0},
		{"legacy separator at index 3", State{LastCodeSeparatorIdx: 3}, 4},
		{"separator at index 0", State{ScriptCodeStart: 1}, 1},
		{"ScriptCodeStart wins", State{LastCodeSeparatorIdx: 3, ScriptCodeStart: 1}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			th := newThread(t)
			st := tc.state
			st.Scripts = th.scripts
			th.SetState(&st)
			require.Equal(t, tc.wantStart, th.scriptCodeStart)
		})
	}

	t.Run("flags are re-derived", func(t *testing.T) {
		t.Parallel()
		th := newThread(t)
		require.False(t, th.dstack.verifyMinimalData)
		require.False(t, th.afterGenesis)

		st := th.State()
		st.Flags = scriptflag.VerifyMinimalData | scriptflag.UTXOAfterGenesis | scriptflag.UTXOAfterChronicle
		th.SetState(st)
		require.True(t, th.dstack.verifyMinimalData)
		require.True(t, th.astack.verifyMinimalData)
		require.True(t, th.afterGenesis)
		require.True(t, th.afterChronicle)
		require.Equal(t, MaxScriptNumberLengthAfterChronicle, th.dstack.maxNumLength)
		require.True(t, th.hasFlag(scriptflag.Chronicle))
		require.True(t, th.enforceNonMalleability) // no transaction: version 0
	})
}

// TestGHSACoreSetStateBip16 checks that resuming from a captured State does
// not turn P2SH evaluation off. The redeem script is OP_0, so a
// one-shot run gives ErrEvalFalse; if the resumed thread doesn't re-derive
// t.bip16 from the restored flags and scripts, the redeem script never
// runs, and the locking script's own OP_EQUAL -- which necessarily matches,
// since the embedded hash is hash160(redeem) by construction -- wrongly
// counts as the whole spend succeeding.
func TestGHSACoreSetStateBip16(t *testing.T) {
	t.Parallel()

	redeem := []byte{script.Op0}
	hash := crypto.Hash160(redeem)
	lock := script.NewFromBytes(append(append([]byte{script.OpHASH160, script.OpDATA20}, hash...), script.OpEQUAL))
	unlock := script.NewFromBytes(canonicalPush(redeem))

	run := func(t *testing.T, opts ...ExecutionOptionFunc) error {
		t.Helper()
		// P2SH is only evaluated for an output created before Genesis.
		return NewEngine().Execute(append(opts, WithBeforeGenesis(), WithScripts(lock, unlock))...)
	}

	oneShot := run(t, WithP2SH())
	require.True(t, errs.IsErrorCode(oneShot, errs.ErrEvalFalse), "%v", oneShot)

	// Capture the state right as the locking script starts and resume
	// without WithP2SH: State.Flags alone, restored by SetState, must be
	// enough to bring P2SH evaluation back -- the same as a one-shot run
	// with those flags and scripts would.
	rec := &coreStateAtScript{script: 1}
	require.Error(t, run(t, WithP2SH(), WithDebugger(rec)))
	require.NotNil(t, rec.state)

	resumed := run(t, WithState(rec.state))
	require.True(t, errs.IsErrorCode(resumed, errs.ErrEvalFalse), "%v", resumed)
}

// TestGHSACoreSetStateSigPushOnly checks that a resumed thread enforces
// SigPushOnly against the restored State.Flags and State.Scripts[0], not
// whatever the thread's own flags required when it was first built.
func TestGHSACoreSetStateSigPushOnly(t *testing.T) {
	t.Parallel()

	// OP_NOP OP_1: not push only.
	th, err := createThread(&execOpts{
		lockingScript:   coreScript(t, "51"),
		unlockingScript: coreScript(t, "6151"),
	})
	require.NoError(t, err)
	require.False(t, th.hasFlag(scriptflag.VerifySigPushOnly))

	st := th.State()
	st.Flags |= scriptflag.VerifySigPushOnly | scriptflag.UTXOAfterGenesis
	th.SetState(st)

	require.True(t, errs.IsErrorCode(th.stateErr, errs.ErrNotPushOnly), "%v", th.stateErr)
}

// TestGHSACoreSetStateCleanStackWithoutP2SH checks that a resumed thread
// rejects CLEANSTACK-without-P2SH the same way a one-shot run does, and
// that Execute -- via WithState -- surfaces the error SetState records,
// since SetState itself has no error return.
func TestGHSACoreSetStateCleanStackWithoutP2SH(t *testing.T) {
	t.Parallel()

	lock := coreScript(t, "51")
	unlock := coreScript(t, "51")

	th, err := createThread(&execOpts{lockingScript: lock, unlockingScript: unlock})
	require.NoError(t, err)
	st := th.State()
	st.Flags |= scriptflag.VerifyCleanStack // no Bip16

	err = NewEngine().Execute(WithScripts(lock, unlock), WithState(st))
	require.True(t, errs.IsErrorCode(err, errs.ErrInvalidFlags), "%v", err)
}

// TestGHSACoreSetStateInvalidFlagCombination checks that resuming from a
// State whose flags a one-shot run rejects (UTXOAfterChronicle without
// UTXOAfterGenesis) fails the same way instead of keeping the thread's
// previous flags.
func TestGHSACoreSetStateInvalidFlagCombination(t *testing.T) {
	t.Parallel()

	lock := coreScript(t, "51")
	unlock := coreScript(t, "51")

	err := NewEngine().Execute(WithScripts(lock, unlock), WithFlags(scriptflag.UTXOAfterChronicle))
	require.True(t, errs.IsErrorCode(err, errs.ErrInvalidFlags), "one-shot: %v", err)

	th, err := createThread(&execOpts{lockingScript: lock, unlockingScript: unlock})
	require.NoError(t, err)
	st := th.State()
	st.Flags = scriptflag.UTXOAfterChronicle

	err = NewEngine().Execute(WithScripts(lock, unlock), WithState(st))
	require.True(t, errs.IsErrorCode(err, errs.ErrInvalidFlags), "resumed: %v", err)
}

// TestGHSACoreSetStateErrorSurfacesThroughStep checks that Step returns a
// stateErr a SetState call left on the thread, for a Debugger that calls
// SetState directly (StateHandler is a public interface) rather than
// through WithState.
func TestGHSACoreSetStateErrorSurfacesThroughStep(t *testing.T) {
	t.Parallel()

	th, err := createThread(&execOpts{
		lockingScript:   coreScript(t, "51"),
		unlockingScript: coreScript(t, "51"),
	})
	require.NoError(t, err)

	st := th.State()
	st.Flags |= scriptflag.VerifyCleanStack
	th.SetState(st)

	done, stepErr := th.Step()
	require.True(t, done)
	require.True(t, errs.IsErrorCode(stepErr, errs.ErrInvalidFlags), "%v", stepErr)
}

// TestGHSACoreSetStateShortScripts checks that SetState guards a crafted
// State with fewer than the two scripts every thread has (an unlocking and
// a locking script) instead of panicking when checkParsedScriptFlags
// indexes into them.
func TestGHSACoreSetStateShortScripts(t *testing.T) {
	t.Parallel()

	th, err := createThread(&execOpts{
		lockingScript:   coreScript(t, "51"),
		unlockingScript: coreScript(t, "51"),
	})
	require.NoError(t, err)

	st := th.State()
	st.Scripts = st.Scripts[:1]
	require.NotPanics(t, func() { th.SetState(st) })
	require.True(t, errs.IsErrorCode(th.stateErr, errs.ErrInvalidParams), "%v", th.stateErr)
}

// TestGHSACoreJoinedScriptCode checks that a Chronicle scriptSig CHECKSIG's
// scriptCode is decoded as one script when the scriptSig ends in an
// undecodable push, the way node reads scriptSig + scriptPubKey.
func TestGHSACoreJoinedScriptCode(t *testing.T) {
	t.Parallel()

	parser := DefaultOpcodeParser{nodeExact: true}
	parse := func(h string) ParsedScript {
		pscr, err := parser.Parse(coreScript(t, h))
		require.NoError(t, err)
		return pscr
	}
	tests := []struct {
		name, unlock, lock string
		want               []string // hex of each instruction of the scriptCode
	}{
		{"tail swallows the codesep", "ac6a4c01", "ab51", []string{"ac", "6a", "4c01ab", "51"}},
		{"tail stays undecodable", "ac6a4c05", "ab51", []string{"ac", "6a", "4c05ab51"}},
		{"decodable scriptSig joins as is", "ac6a01ab", "ab51", []string{"ac", "6a", "01ab", "ab", "51"}},
		{"empty lock", "ac6a4c", "", []string{"ac", "6a", "4c"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			th := &thread{flags: scriptflag.Chronicle, scripts: []ParsedScript{parse(tt.unlock), parse(tt.lock)}}
			got := th.subScriptForChecksig()
			ops := make([]string, len(got))
			for i := range got {
				b, err := got[i].bytes()
				require.NoError(t, err)
				ops[i] = hex.EncodeToString(b)
			}
			require.Equal(t, tt.want, ops)
		})
	}
}

// TestGHSACoreParseModes checks that a zero-value DefaultOpcodeParser keeps
// its historical behaviour for callers outside the engine, while the engine's
// node-exact parse decodes past a top-level OP_RETURN and defers a malformed
// push until it is reached.
func TestGHSACoreParseModes(t *testing.T) {
	t.Parallel()

	scr := coreScript(t, "0168776a0024dc")

	legacy, err := (&DefaultOpcodeParser{}).Parse(scr)
	require.NoError(t, err)
	require.Len(t, legacy, 3)
	require.Equal(t, script.OpRETURN, legacy[2].Value())
	require.Equal(t, []byte{0x00, 0x24, 0xdc}, legacy[2].Data)

	exact := DefaultOpcodeParser{nodeExact: true}
	pscr, err := exact.Parse(scr)
	require.NoError(t, err)
	require.Len(t, pscr, 5)
	require.Equal(t, script.OpRETURN, pscr[2].Value())
	require.Empty(t, pscr[2].Data)
	require.Equal(t, script.Op0, pscr[3].Value())
	require.True(t, pscr[4].isMalformed())
	require.Equal(t, []byte{0x24, 0xdc}, pscr[4].Data)
	unparsed, err := exact.Unparse(pscr)
	require.NoError(t, err)
	require.Equal(t, []byte(*scr), []byte(*unparsed))

	// A malformed push outside an OP_RETURN tail is still a parse error for
	// the zero-value parser, but only a deferred failure for the engine.
	bad := coreScript(t, "5124dc")
	_, err = (&DefaultOpcodeParser{}).Parse(bad)
	require.True(t, errs.IsErrorCode(err, errs.ErrMalformedPush))
	pbad, err := exact.Parse(bad)
	require.NoError(t, err)
	require.Len(t, pbad, 2)
	require.True(t, pbad[1].isMalformed())
}

// TestGHSACoreExecuteRecoversPanics checks that a panic raised while
// executing a script is returned as an ErrInternal error instead of crashing
// the caller.
func TestGHSACoreExecuteRecoversPanics(t *testing.T) {
	t.Parallel()

	err := NewEngine().Execute(
		WithScripts(coreScript(t, "51"), coreScript(t, "51")),
		WithDebugger(&corePanicDebugger{}),
	)
	require.True(t, errs.IsErrorCode(err, errs.ErrInternal), "%v", err)
}

// corePanicDebugger panics before the first opcode executes.
type corePanicDebugger struct{ nopDebugger }

func (*corePanicDebugger) BeforeExecuteOpcode(*State) { panic("boom") }

// TestGHSACoreSetStateStackMemory checks that a resumed thread keeps counting
// the stack memory an earlier script left on the alt stack, like a one-shot
// run does.
func TestGHSACoreSetStateStackMemory(t *testing.T) {
	t.Parallel()

	// scriptSig pushes 60 bytes to the alt stack; the lock pushes 60 more.
	unlock := append(append([]byte{0x3c}, make([]byte, 60)...), script.OpTOALTSTACK)
	lock := append(append([]byte{0x3c}, make([]byte, 60)...), script.OpDROP, script.Op1)
	run := func(t *testing.T, opts ...ExecutionOptionFunc) error {
		t.Helper()
		opts = append(
			opts,
			WithScripts(script.NewFromBytes(lock), script.NewFromBytes(unlock)),
			WithAfterGenesis(),
			WithMaxStackMemory(100+2*stackElementOverhead),
		)
		return NewEngine().Execute(opts...)
	}

	oneShot := run(t)
	require.True(t, errs.IsErrorCode(oneShot, errs.ErrStackOverflow), "%v", oneShot)

	// Capture the state when the lock starts and resume from it.
	rec := &coreStateAtScript{script: 1}
	require.Error(t, run(t, WithDebugger(rec)))
	require.NotNil(t, rec.state)
	require.Equal(t, int64(60+stackElementOverhead), rec.state.StackMemory)

	resumed := run(t, WithState(rec.state))
	require.True(t, errs.IsErrorCode(resumed, errs.ErrStackOverflow), "%v", resumed)
}

// coreStateAtScript records the thread state before the first opcode of the
// given script.
type coreStateAtScript struct {
	nopDebugger

	script int
	state  *State
}

func (d *coreStateAtScript) BeforeExecuteOpcode(s *State) {
	if d.state == nil && s.ScriptIdx == d.script && s.OpcodeIdx == 0 {
		d.state = s
	}
}
