package interpreter

import (
	"context"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// ExecutionOptionFunc for setting execution options.
type ExecutionOptionFunc func(p *execOpts)

// WithTx configure the execution to run again a tx.
func WithTx(tx *transaction.Transaction, inputIdx int, prevOutput *transaction.TransactionOutput) ExecutionOptionFunc {
	return func(p *execOpts) {
		p.tx = tx
		p.previousTxOut = prevOutput
		p.inputIdx = inputIdx
	}
}

// WithScripts configure the execution to run again a set of *script.Script.
func WithScripts(lockingScript, unlockingScript *script.Script) ExecutionOptionFunc {
	return func(p *execOpts) {
		p.lockingScript = lockingScript
		p.unlockingScript = unlockingScript
	}
}

// WithBeforeGenesis configures the execution to operate in a pre-Genesis
// context: the original script limits (500 ops, 520-byte elements, 4-byte
// numbers, ...) and disabled opcodes apply. Use it when verifying a spend of a
// UTXO created before the Genesis upgrade (block 620538 on mainnet).
//
// If a later epoch is also requested (WithAfterGenesis, WithAfterChronicle or
// a UTXO epoch flag via WithFlags), the most recent of the requested epochs
// wins, regardless of option order.
//
// Like the other epoch options it does not stop Execute enabling
// SIGHASH_FORKID when no flag option is given (see WithForkID).
func WithBeforeGenesis() ExecutionOptionFunc {
	return func(p *execOpts) {
		p.epochSet = true
	}
}

// WithAfterGenesis configures the execution to operate in an after-Genesis,
// pre-Chronicle context. Use it when verifying a spend of a UTXO created after
// the Genesis upgrade but before the Chronicle upgrade. It marks the spent
// output as created after Genesis, which also implies that the spend itself
// is validated under Genesis rules (see WithGenesis).
//
// Combined with WithAfterChronicle (in any order), the execution is
// after-Chronicle.
//
// Every block since Genesis enables SIGHASH_FORKID, so this also sets
// scriptflag.EnableSighashForkID (see WithForkID).
func WithAfterGenesis() ExecutionOptionFunc {
	return func(p *execOpts) {
		p.flagsSet = true
		p.epochSet = true
		p.flags.AddFlag(scriptflag.UTXOAfterGenesis)
		p.flags.AddFlag(scriptflag.EnableSighashForkID)
	}
}

// WithAfterChronicle configures the execution to operate in an after-Chronicle
// context. This also implies after-Genesis. Chronicle is the BSV v1.2.0
// protocol upgrade, active on mainnet since April 2026. It marks the spent
// output as created after Chronicle, which also implies that the spend itself
// is validated under Chronicle rules (see WithChronicle). Like
// WithAfterGenesis, it also sets scriptflag.EnableSighashForkID.
//
// This is the default when no epoch is specified (see Engine.Execute), so it
// only needs to be passed explicitly alongside WithFlags, or for clarity.
func WithAfterChronicle() ExecutionOptionFunc {
	return func(p *execOpts) {
		p.flagsSet = true
		p.epochSet = true
		p.flags.AddFlag(scriptflag.UTXOAfterGenesis)
		p.flags.AddFlag(scriptflag.UTXOAfterChronicle)
		p.flags.AddFlag(scriptflag.EnableSighashForkID)
	}
}

// WithGenesis configure the execution to validate the spend under Genesis
// rules, regardless of when the spent output was created. Use it together
// with WithAfterGenesis only when the spent output was also created after
// Genesis. Like WithAfterGenesis, it also sets scriptflag.EnableSighashForkID.
//
// It counts as naming the UTXO epoch: without WithAfterGenesis or
// WithAfterChronicle the spent output is taken as created before Genesis,
// not as after-Chronicle (the default when no epoch is named).
func WithGenesis() ExecutionOptionFunc {
	return func(p *execOpts) {
		p.flagsSet = true
		p.epochSet = true
		p.flags.AddFlag(scriptflag.Genesis)
		p.flags.AddFlag(scriptflag.EnableSighashForkID)
	}
}

// WithChronicle configure the execution to validate the spend under Chronicle
// rules, regardless of when the spent output was created. This also implies
// Genesis. Use it together with WithAfterChronicle only when the spent output
// was also created after Chronicle. Like WithAfterGenesis, it also sets
// scriptflag.EnableSighashForkID.
//
// Like WithGenesis it counts as naming the UTXO epoch, so on its own it
// validates the spend of an output created before Genesis.
func WithChronicle() ExecutionOptionFunc {
	return func(p *execOpts) {
		p.flagsSet = true
		p.epochSet = true
		p.flags.AddFlag(scriptflag.Genesis)
		p.flags.AddFlag(scriptflag.Chronicle)
		p.flags.AddFlag(scriptflag.EnableSighashForkID)
	}
}

// WithForkID configure the execution to allow a tx with a fork id.
//
// Every block since the UAHF (mainnet height 478,559) validates scripts with
// this flag: signatures must then use SIGHASH_FORKID and are checked against
// the BIP143 digest. Without it, a signature with the ForkID bit is checked
// against the original digest, as in a block before the UAHF, so verifying a
// current transaction requires WithForkID, one of the era options that imply
// it (WithAfterGenesis, WithAfterChronicle, WithGenesis, WithChronicle) or a
// full flag word, for example from
// scriptflag.ActivationHeights.BlockValidationFlags. Flags passed with
// WithFlags are used exactly as given.
//
// Breaking change from v1.6.0: as in bitcoin-sv, the flag implies
// VerifyStrictEncoding, under which a signature without SIGHASH_FORKID fails
// with errs.ErrMustUseForkID.
func WithForkID() ExecutionOptionFunc {
	return func(p *execOpts) {
		p.flagsSet = true
		p.flags.AddFlag(scriptflag.EnableSighashForkID)
	}
}

// WithP2SH configure the execution to allow a P2SH output.
func WithP2SH() ExecutionOptionFunc {
	return func(p *execOpts) {
		p.flagsSet = true
		p.flags.AddFlag(scriptflag.Bip16)
	}
}

// WithFlags configure the execution with the provided flags: bitcoin-sv's
// flag word, used exactly as given. Unlike WithForkID and the era options it
// does not add EnableSighashForkID, and without that flag every signature is
// checked against the legacy digest, as in a block before the UAHF.
//
// The UTXO epoch is taken from scriptflag.UTXOAfterGenesis and
// scriptflag.UTXOAfterChronicle, and if neither is set the execution is
// pre-Genesis, exactly as in the SV node. Passing WithFlags therefore
// disables the after-Chronicle default; add WithAfterChronicle (or the UTXO
// epoch flags) to verify under current rules.
//
// Breaking change from v1.6.0: v1.6.0 chose the digest from the signature's
// SIGHASH_FORKID bit alone, whatever the flags. A SIGHASH_FORKID signature
// verified with flags that lack EnableSighashForkID now fails: with
// errs.ErrIllegalForkID when the flags set VerifyStrictEncoding, and
// otherwise because the legacy digest is not what it signed.
func WithFlags(flags scriptflag.Flag) ExecutionOptionFunc {
	return func(p *execOpts) {
		p.flagsSet = true
		p.epochSet = true
		p.flags.AddFlag(flags)
	}
}

// WithMaxStackMemory sets the stack memory limit, in bytes, for spending an
// output created after Genesis. As in bitcoin-sv's LimitedStack, every
// element on the data and alt stacks counts its size plus 32 bytes, and a
// script that would go over the limit fails with errs.ErrStackOverflow
// (node's SCRIPT_ERR_STACK_SIZE).
//
// Without this option the limit is DefaultMaxStackMemory, node's default
// relay policy: scripts are mostly verified before their transaction is
// mined, and nodes do not relay one that needs more. Blocks are validated
// with no limit (DEFAULT_STACK_MEMORY_USAGE_CONSENSUS_AFTER_GENESIS is
// INT64_MAX, consensus/consensus.h:82); pass math.MaxInt64 to match that,
// which lets a script use as much memory as the host has. A limit of zero or
// less selects DefaultMaxStackMemory. Outputs created before Genesis have no
// stack memory limit, as in node, since their element size and count limits
// bound the stacks.
func WithMaxStackMemory(limit int64) ExecutionOptionFunc {
	return func(p *execOpts) {
		p.maxStackMemory = limit
	}
}

// WithDebugger enable execution debugging with the provided configured debugger.
// It is important to note that when this setting is applied, it enables thread
// state cloning, at every configured debug step.
func WithDebugger(debugger Debugger) ExecutionOptionFunc {
	return func(p *execOpts) {
		p.debugger = debugger
	}
}

// WithContext stops execution once ctx is done, with an error for which both
// errs.IsErrorCode(err, errs.ErrExecutionCancelled) and errors.Is(err,
// ctx.Err()) hold. Without it, or with a nil ctx or one that is never done,
// execution has no time limit.
//
// As in node, ctx is checked before every opcode (interpreter.cpp:441-445)
// and inside OP_CHECKMULTISIG's signature loop (interpreter.cpp:1589) and
// OP_LSHIFT's and OP_RSHIFT's loops (interpreter.cpp:1144,1178), so
// execution stops within about one opcode. The slowest single opcodes at
// era limits, such as OP_DIV of a 32 MB number, take a few tenths of a
// second.
//
// bitcoin-sv bounds the time it spends validating a transaction for relay
// (-maxstdtxvalidationduration, 3 ms by default, and
// -maxnonstdtxvalidationduration, 1 s; txn_validation_config.h) and puts no
// limit on block validation. The interpreter has no limit of its own.
func WithContext(ctx context.Context) ExecutionOptionFunc {
	return func(p *execOpts) {
		p.ctx = ctx
	}
}

// WithState inject the provided state into the execution thread. This assumes
// that the state is correct for the scripts provided.
//
// NOTE: This is highly experimental and is unstable when used with unintended states,
// and likely still when used in a happy path scenario. Therefore, it is recommended
// to only be used for debugging purposes.
//
// The safest recommended *interpreter.State records for a given script can be
// are those which can be captured during `debugger.BeforeStep` and `debugger.AfterStep`.
//
// Execute re-derives from state.Flags and state.Scripts everything a
// one-shot run derives from its flags and scripts, including whether the
// spend is evaluated as P2SH, and fails as a one-shot run would when they do
// not go together (errs.ErrInvalidFlags for CLEANSTACK without P2SH, for
// instance). state.Scripts must hold at least the unlocking and the locking
// script (errs.ErrInvalidParams otherwise). A Debugger that calls SetState
// itself gets such an error from the next Step.
func WithState(state *State) ExecutionOptionFunc {
	return func(p *execOpts) {
		p.state = state
	}
}
