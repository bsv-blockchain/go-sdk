package interpreter

// Regression tests for GHSA-rh54-8fpg-8wwf, signature-checking area:
// SIGHASH_CHRONICLE hash types, MUST_USE_FORKID, legacy digest selection
// before UAHF, CHECKSIG in a post-Chronicle unlocking script and exact
// FindAndDelete matching, plus NULLFAIL with an off-curve pubkey and pubkey
// encoding checks with an empty signature. Every table-driven case below is
// a reproducer verified against bitcoin-sv (GoBDK): the expected outcome is
// the real bitcoin-sv node's, which the fixed interpreter matches. Helper
// names use the "sig" prefix to avoid clashing with the numeric-opcode test
// file.

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/errs"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// sigNodeWordToFlags maps node flag bits to scriptflag.Flag, so a node flag
// word from the reproducers can be embedded directly.
func sigNodeWordToFlags(word uint32) scriptflag.Flag {
	var f scriptflag.Flag
	add := func(bit uint32, flag scriptflag.Flag) {
		if word&bit != 0 {
			f |= flag
		}
	}
	add(1<<0, scriptflag.Bip16)
	add(1<<1, scriptflag.VerifyStrictEncoding)
	add(1<<2, scriptflag.VerifyDERSignatures)
	add(1<<3, scriptflag.VerifyLowS)
	add(1<<4, scriptflag.StrictMultiSig)
	add(1<<5, scriptflag.VerifySigPushOnly)
	add(1<<6, scriptflag.VerifyMinimalData)
	add(1<<7, scriptflag.DiscourageUpgradableNops)
	add(1<<8, scriptflag.VerifyCleanStack)
	add(1<<9, scriptflag.VerifyCheckLockTimeVerify)
	add(1<<10, scriptflag.VerifyCheckSequenceVerify)
	add(1<<13, scriptflag.VerifyMinimalIf)
	add(1<<14, scriptflag.VerifyNullFail)
	add(1<<16, scriptflag.EnableSighashForkID)
	add(1<<18, scriptflag.Genesis)
	add(1<<19, scriptflag.UTXOAfterGenesis)
	add(1<<20, scriptflag.Chronicle)
	add(1<<21, scriptflag.UTXOAfterChronicle)
	return f
}

// sigWordCase is one reproducer verified against bitcoin-sv (GoBDK): a
// transaction, its previous-outputs' locking scripts (one per input, in
// order), and per node flag word whether the real node accepts it.
type sigWordCase struct {
	name    string
	txHex   string
	locks   []string
	sats    []uint64
	perWord map[uint32]bool // node/sdk verdict: true = valid, false = invalid
}

func (c sigWordCase) run(t *testing.T) {
	t.Helper()

	// Execute sets each input's source output on the transaction, so every
	// parallel subtest decodes its own copy.
	build := func(t *testing.T) (*transaction.Transaction, []*transaction.TransactionOutput) {
		t.Helper()
		tx, err := transaction.NewTransactionFromHex(c.txHex)
		require.NoError(t, err)

		prevs := make([]*transaction.TransactionOutput, len(tx.Inputs))
		for i := range tx.Inputs {
			lockBytes, hexErr := hex.DecodeString(c.locks[i])
			require.NoError(t, hexErr)
			sats := uint64(1000)
			if i < len(c.sats) && c.sats[i] != 0 {
				sats = c.sats[i]
			}
			prevs[i] = &transaction.TransactionOutput{LockingScript: script.NewFromBytes(lockBytes), Satoshis: sats}
		}
		return tx, prevs
	}

	for word, wantValid := range c.perWord {
		t.Run(fmt.Sprintf("word=0x%06x", word), func(t *testing.T) {
			t.Parallel()
			tx, prevs := build(t)
			flags := sigNodeWordToFlags(word)

			var gotErr error
			for i := range tx.Inputs {
				if gotErr = NewEngine().Execute(WithTx(tx, i, prevs[i]), WithFlags(flags)); gotErr != nil {
					break
				}
			}

			if wantValid {
				require.NoError(t, gotErr, "%s: expected valid under word 0x%06x", c.name, word)
			} else {
				require.Error(t, gotErr, "%s: expected invalid under word 0x%06x", c.name, word)
			}
		})
	}
}

// TestGHSASigOracleCases embeds the signature-checking reproducers verified
// against bitcoin-sv (GoBDK), including the nullfail-offcurve-pk and
// *emptysig-badpktype cases (GHSA-rh54-8fpg-8wwf).
func TestGHSASigOracleCases(t *testing.T) {
	t.Parallel()

	cases := []sigWordCase{
		{
			// SIGHASH_CHRONICLE (0x61) via OP_CHECKSIG must be accepted
			// post-Chronicle: checkHashTypeEncoding must mask the Chronicle
			// bit out of the base-type definedness check and treat a
			// Chronicle-enabled spend's Chronicle-bit signature as legal
			// (thread.go's checkHashTypeEncoding).
			name:  "SIGHASH_CHRONICLE via CHECKSIG",
			txHex: "0200000001fe36cabf1bda3fadc611f3f5fe3522a21f196de9e3bae7c6c1334615ae7d247c0000000049483045022100d3c30fd1dcb27ad8a113961b2d7da02c09afd6b33a9645cdd4ac2de16e2ceb2d022024531a2fe6b42f0dcc640b35e199174d54a02ef40474d6dcbbd078e92968ceec61ffffffff02010000000000000001510200000000000000015100000000",
			locks: []string{"2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac"},
			perWord: map[uint32]bool{
				0x3D462F: true,
				0x3D47FF: true,
			},
		},
		{
			// Same bug, reached via OP_CHECKMULTISIG (1-of-1) --
			// confirms the fix is not CHECKSIG-specific.
			name:  "SIGHASH_CHRONICLE via CHECKMULTISIG",
			txHex: "0200000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000004a00483045022100d94305a0cadb89894b192b190dc06740592ad3214186c0f04564917598fd5477022047eec00faef36e34862159bc3e764f27e55b3e9be8d58f8fb13d2ca61e22549a61ffffffff010100000000000000015100000000",
			locks: []string{"512103155263f56fead84f623e35b2fd370e98df794668f753131cb9778d7ad18831c451ae"},
			perWord: map[uint32]bool{
				0x3D462F: true,
				0x3D47FF: true,
			},
		},
		{
			// MUST_USE_FORKID must be enforced once EnableSighashForkID is
			// set, even for a hash type whose base type is otherwise legal
			// (thread.go's checkHashTypeEncoding: the check must run outside
			// the (dead, pre-fix) "has ForkID" branch).
			name:  "MUST_USE_FORKID enforced",
			txHex: "02000000019e03f63c990f56f6b833906c0e7ce79997d714f1fad7ddb269fd540ea6a69831000000004847304402204e6ac1a186fb8890262510729eb59db4e12ac850a6f0a2642a2f6823eeee8a1502201603606dad2bcd6caeb1e6422216dc36592e13e5700a0d68eca9c59bf2e35d1001ffffffff02010000000000000001510200000000000000015100000000",
			locks: []string{"2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac"},
			perWord: map[uint32]bool{
				0x3D462F: false,
				0x3D47FF: false,
			},
		},
		{
			// A pre-UAHF word (no SIGHASH_FORKID in the flags) must
			// hash the ORIGINAL/legacy digest even though input 1's
			// signature carries the ForkID bit -- the interpreter's own
			// EnableSighashForkID flag, not just the signature's bit, must
			// gate BIP143 selection (CalcInputSignatureHashWithForkIDEnabled).
			name:  "pre-UAHF digest selection ignores sig's ForkID bit",
			txHex: "02000000031c03d65739de2b55f51b600abb4b3eba4c3bbc3c62244bf10eaa53b6c63d39ad000000004948304502210080089464b438a3c3b800805194aaf845845ff0fb73dd55da5bc32a2ba016a0da022003e74a9cf63659240c2814006ada6fb982fdf01c292bff03da79692cafb6c5cd01ffffffff140155ec0e942dc40a8f418e720b4e996e50788fb0b5a4e23a5659df6f939063000000004847304402207acc9a382964cf2c03c83df3f877ddaa942ecfd5fb48c9e4636b1ee46fea0a29022022373d2f768a83c2b5f0a843c0e48bd19716922c4831ba083a4a0e25f14005a641ffffffff8e47aab4115643d43d0428135ef7eb3d37472c0cfec5e3eda8339921f8efeb4a000000004847304402206e1f94c990cb392dab5e7e46faa775bdfeea9ab8787cba307de9c3f7bcec046b022015bedb0d8f5e295de76de219de674c41649057f8e77494855c868b709e14667901ffffffff02010000000000000001510200000000000000015100000000",
			locks: []string{
				"2103913a7b50432835163ebc6aa9cad8c3f52e6a37df35be520213a2fa5c0be9b353ac",
				"2103c10f4fba86c5439080cb87226bc19b344eb56e6f4f6db673b6674fdfa63f6d57ac",
				"2102dae175dcbf94e5b79a4a53a67ba1259b7825079ec03b2c39101b9438eff5d904ac",
			},
			perWord: map[uint32]bool{
				0x000605: true,
			},
		},
		{
			// A post-Chronicle CHECKSIG executing directly inside the
			// unlocking script must append the full locking script to
			// scriptCode (subScriptForChecksig). SIGPUSHONLY is stripped
			// from the standard words to isolate this from the unrelated
			// (already-fixed) Chronicle-version-gate divergence, exactly as
			// the original reproducer does.
			name:  "CHECKSIG-in-scriptSig appends locking script post-Chronicle",
			txHex: "0200000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000006c47304402200ba3d2bdec81baf08ad22865b856becea61d2ba002b6f7160174a1fe75a436a70220384d83cea3d40f9d4cc019eada8c6447b84dbd9f4733bf0d0b741e513953bce5412103fd0b582b2056e9ffd5eaf78c478b6532dbf9db897ad95024f1d1533894404135abacffffffff010100000000000000015100000000",
			locks: []string{"61"},
			perWord: map[uint32]bool{
				0x3D462F &^ (1 << 5): true,
				0x3D47FF &^ (1 << 5): true,
			},
		},
		{
			// Control: identical shape, but PRE-Chronicle -- the
			// locking script must NOT be appended (node's checksigData
			// append is gated on IsChronicle(flags)), so this must keep
			// matching regardless of the scriptSig CHECKSIG fix.
			name:  "control: CHECKSIG-in-scriptSig pre-Chronicle",
			txHex: "0200000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000006c473044022004ae4429dac4d0716aa2e3b48d9a7d419ac164f7d80aa9c94bb14d547b6d7cd0022003fab385531fee4ed0a42f5f9c95103b948d060b126afa2f1c992a7d4311b971412103fd0b582b2056e9ffd5eaf78c478b6532dbf9db897ad95024f1d1533894404135abacffffffff010100000000000000015100000000",
			locks: []string{"61"},
			perWord: map[uint32]bool{
				0x0D462F &^ (1 << 5): true,
				0x0D47FF &^ (1 << 5): true,
			},
		},
		{
			// A decoy push (sig-bytes || 0xFF) must NOT be stripped
			// from scriptCode by removeOpcodeByData -- only an exact
			// canonical-push match may be removed (node's
			// FindAndDelete(CScript(vchSig)) never does substring
			// containment). The buggy bytes.Contains version wrongly
			// accepted this transaction; node (and the fix) reject it.
			name:  "decoy push must not be stripped (accept-invalid bug)",
			txHex: "0200000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000048473044022076da282332397535a00082407bcb41b51aa0072cc8ef229d7e18c43b52f74a2602201f7bdf4673b61c57ba46ebcb82f1131269d35b05be51ebc2de32fadf690b925201ffffffff010100000000000000015100000000",
			locks: []string{"483044022076da282332397535a00082407bcb41b51aa0072cc8ef229d7e18c43b52f74a2602201f7bdf4673b61c57ba46ebcb82f1131269d35b05be51ebc2de32fadf690b925201ff752103aa5b77bcfe0f74b107c63ff2dd0948ed352a7574f0bfd2176dfe18a878681f1aac"},
			perWord: map[uint32]bool{
				0x0E: false,
			},
		},
		{
			// Control: an exact canonical self-embedded signature
			// (no decoy) must still be fully stripped, exactly as before.
			name:  "control: exact self-embedded signature is stripped",
			txHex: "0200000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000006b47304402203e14a3165297b12d00201aba97e5d5cd35b9afd3c4ba34f144ab141a1b78f2890220216813b01fe7ead40b8b83b9b75b0c6749a0e4f749007ea0127c02b30d535c12012102a5fde6c145e0cac3df9700a081fde5216491bfc2e19a1eb9db7339cc4c2dc553acffffffff010100000000000000015100000000",
			locks: []string{""},
			perWord: map[uint32]bool{
				0x0E: true,
			},
		},
		{
			// nullfail-offcurve-pk (x=5): OP_CHECKSIG must still
			// treat an unparseable (off-curve) pubkey/failed verify as
			// fSuccess=false subject to NULLFAIL, rather than short-circuit
			// returning false before the NULLFAIL check runs.
			name:  "nullfail-offcurve-pk x=5",
			txHex: "010000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff010100000000000000015100000000",
			locks: []string{"0930060201010201014121020000000000000000000000000000000000000000000000000000000000000005ac91"},
			perWord: map[uint32]bool{
				0x3D462F: false,
				0x3D47FF: false,
			},
		},
		{
			// Same shape with a different off-curve x-coordinate (x=7).
			name:  "nullfail-offcurve-pk x=7",
			txHex: "010000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff010100000000000000015100000000",
			locks: []string{"0930060201010201014121020000000000000000000000000000000000000000000000000000000000000007ac91"},
			perWord: map[uint32]bool{
				0x3D462F: false,
				0x3D47FF: false,
			},
		},
		{
			// checksig emptysig badpktype: CheckPubKeyEncoding must
			// run even when the signature is empty. Under STRICTENC
			// (0x3D462F/0x3D47FF/0x010607) the bad pubkey type is a hard
			// error; under the pre-UAHF word (no STRICTENC) it is not, and
			// the empty-sig CHECKSIG's false is negated by OP_NOT.
			name:  "checksig emptysig badpktype",
			txHex: "010000000122222222222222222222222222222222222222222222222222222222222222220000000000ffffffff010100000000000000015100000000",
			locks: []string{"0021051111111111111111111111111111111111111111111111111111111111111111ac91"},
			perWord: map[uint32]bool{
				0x3D462F: false,
				0x3D47FF: false,
				0x010607: false,
				0x000605: true,
			},
		},
		{
			// multisig emptysig badpktype: same rule inside
			// OP_CHECKMULTISIG's per-iteration loop.
			name:  "multisig emptysig badpktype",
			txHex: "010000000122222222222222222222222222222222222222222222222222222222222222220000000000ffffffff010100000000000000015100000000",
			locks: []string{"0000512105111111111111111111111111111111111111111111111111111111111111111151ae91"},
			perWord: map[uint32]bool{
				0x3D462F: false,
				0x3D47FF: false,
				0x010607: false,
				0x000605: true,
			},
		},
		{
			// multisig emptysig 2 keys 2nd badpktype: the SECOND
			// pubkey attempted (after the first, empty-sig-paired key is
			// skipped) still has its encoding checked before any signature
			// verification is attempted.
			name:  "multisig emptysig 2 keys 2nd badpktype",
			txHex: "010000000122222222222222222222222222222222222222222222222222222222222222220000000000ffffffff010100000000000000015100000000",
			locks: []string{"000051210200000000000000000000000000000000000000000000000000000000000000052105111111111111111111111111111111111111111111111111111111111111111152ae91"},
			perWord: map[uint32]bool{
				0x3D462F: false,
				0x010607: false,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

// sigParse parses raw script bytes into a ParsedScript for the tests below.
func sigParse(t *testing.T, b []byte) ParsedScript {
	t.Helper()
	pops, err := (&DefaultOpcodeParser{nodeExact: true}).Parse(script.NewFromBytes(b))
	require.NoError(t, err)
	return pops
}

// TestGHSASigRemoveOpcodeByDataExactMatch is a focused unit test for
// opcodeparser.go's removeOpcodeByData: only a push whose data is
// byte-for-byte identical to the target may be removed, mirroring node's
// FindAndDelete(CScript(data)) -- never a substring match, and (for an
// empty target, as OP_CHECKMULTISIG produces for an empty declared
// signature) never a non-push opcode that merely also carries nil Data.
func TestGHSASigRemoveOpcodeByDataExactMatch(t *testing.T) {
	t.Parallel()

	sigBytes := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01}

	t.Run("exact match is removed", func(t *testing.T) {
		t.Parallel()
		var lock script.Script
		require.NoError(t, lock.AppendPushData(sigBytes))
		require.NoError(t, lock.AppendOpcodes(script.OpCHECKSIG))

		out := sigParse(t, removeOpcodeByData(lock, sigBytes))
		require.Len(t, out, 1)
		require.Equal(t, script.OpCHECKSIG, out[0].Value())
	})

	t.Run("decoy push containing the target as a substring is kept", func(t *testing.T) {
		t.Parallel()
		decoy := append(append([]byte{}, sigBytes...), 0xFF)
		var lock script.Script
		require.NoError(t, lock.AppendPushData(decoy))
		require.NoError(t, lock.AppendOpcodes(script.OpCHECKSIG))

		out := sigParse(t, removeOpcodeByData(lock, sigBytes))
		require.Len(t, out, 2, "the decoy push must survive: it is not byte-for-byte equal to the target")
		require.Equal(t, decoy, out[0].Data)
	})

	t.Run("empty target removes only OP_0, never an unrelated non-push opcode", func(t *testing.T) {
		t.Parallel()
		// OP_0 OP_1 OP_DUP OP_CHECKSIG: every non-push opcode here also
		// carries nil Data, so bytes.Equal(pop.Data, nil) alone (without
		// the Op0..OpPUSHDATA4 bound) would spuriously match all of them.
		var lock script.Script
		require.NoError(t, lock.AppendOpcodes(script.Op0, script.Op1, script.OpDUP, script.OpCHECKSIG))

		out := sigParse(t, removeOpcodeByData(lock, nil))
		require.Len(t, out, 3, "only the OP_0 should be removed")
		gotVals := make([]byte, len(out))
		for i, pop := range out {
			gotVals[i] = pop.Value()
		}
		require.Equal(t, []byte{script.Op1, script.OpDUP, script.OpCHECKSIG}, gotVals)
	})
}

// TestGHSASigCheckHashTypeEncoding is a focused unit test for
// checkHashTypeEncoding: it must mask the Chronicle bit out of the base-type
// definedness check, and must enforce MUST_USE_FORKID even for a hash type
// with no ForkID bit at all, while leaving the non-consensus
// VerifyBip143SigHash test-only knob's behavior unchanged.
func TestGHSASigCheckHashTypeEncoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		shf     sighash.Flag
		flags   scriptflag.Flag
		wantErr errs.ErrorCode
	}{
		{
			name:    "Chronicle-bit hash type is defined and legal when Chronicle+ForkID are enabled",
			shf:     sighash.AllForkID | sighash.Chronicle, // 0x61
			flags:   scriptflag.VerifyStrictEncoding | scriptflag.EnableSighashForkID | scriptflag.Chronicle,
			wantErr: errs.ErrOK,
		},
		{
			name:    "Chronicle-bit hash type is illegal when Chronicle is not enabled",
			shf:     sighash.AllForkID | sighash.Chronicle,
			flags:   scriptflag.VerifyStrictEncoding | scriptflag.EnableSighashForkID,
			wantErr: errs.ErrIllegalChronicle,
		},
		{
			name:    "non-ForkID hash type must use ForkID once EnableSighashForkID is set",
			shf:     sighash.All,
			flags:   scriptflag.VerifyStrictEncoding | scriptflag.EnableSighashForkID,
			wantErr: errs.ErrMustUseForkID,
		},
		{
			name:    "non-ForkID hash type is fine when ForkID is not enabled",
			shf:     sighash.All,
			flags:   scriptflag.VerifyStrictEncoding,
			wantErr: errs.ErrOK,
		},
		{
			name:    "ForkID bit set without the flag enabled is illegal",
			shf:     sighash.AllForkID,
			flags:   scriptflag.VerifyStrictEncoding,
			wantErr: errs.ErrIllegalForkID,
		},
		{
			name:    "VerifyBip143SigHash (non-consensus knob) keeps its pre-existing behavior",
			shf:     sighash.AllForkID,
			flags:   scriptflag.VerifyStrictEncoding | scriptflag.VerifyBip143SigHash,
			wantErr: errs.ErrOK,
		},
		{
			name:    "VerifyBip143SigHash + a hash type carrying Chronicle's bit for an unrelated purpose stays undefined",
			shf:     sighash.SingleForkID | sighash.AnyOneCanPay | sighash.Chronicle,
			flags:   scriptflag.VerifyStrictEncoding | scriptflag.VerifyBip143SigHash,
			wantErr: errs.ErrInvalidSigHashType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			th := thread{flags: tt.flags}
			err := th.checkHashTypeEncoding(tt.shf)
			if tt.wantErr == errs.ErrOK {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.True(t, errs.IsErrorCode(err, tt.wantErr), "got %v, want code %v", err, tt.wantErr)
		})
	}
}

// TestGHSASigSubScriptForChecksig is a focused unit test for
// subScriptForChecksig: it must append the full locking script only when
// executing scriptIdx 0 (the raw unlocking script, never a locking script or
// P2SH redeem script) under a Chronicle-era spend.
func TestGHSASigSubScriptForChecksig(t *testing.T) {
	t.Parallel()

	unlockBytes := []byte{script.OpCHECKSIG}
	lockBytes := []byte{script.OpDUP, script.OpCHECKSIG}

	newTh := func(scriptIdx int, chronicle bool) *thread {
		th := &thread{
			scriptIdx: scriptIdx,
			scripts:   []ParsedScript{sigParse(t, unlockBytes), sigParse(t, lockBytes)},
		}
		if chronicle {
			th.flags = scriptflag.Chronicle
		}
		return th
	}

	t.Run("scriptIdx 0 + Chronicle appends the full locking script", func(t *testing.T) {
		t.Parallel()
		th := newTh(0, true)
		got := th.subScriptForChecksig()
		require.Len(t, got, len(unlockBytes)+len(lockBytes))
		require.Equal(t, script.OpCHECKSIG, got[0].Value())
		require.Equal(t, script.OpDUP, got[1].Value())
		require.Equal(t, script.OpCHECKSIG, got[2].Value())
	})

	t.Run("scriptIdx 0 without Chronicle does not append", func(t *testing.T) {
		t.Parallel()
		th := newTh(0, false)
		got := th.subScriptForChecksig()
		require.Len(t, got, len(unlockBytes))
	})

	t.Run("scriptIdx 1 (locking script itself) never appends, even under Chronicle", func(t *testing.T) {
		t.Parallel()
		th := newTh(1, true)
		got := th.subScriptForChecksig()
		require.Len(t, got, len(lockBytes))
	})
}
