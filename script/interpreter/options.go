package interpreter

import (
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
func WithBeforeGenesis() ExecutionOptionFunc {
	return func(p *execOpts) {
		p.epochSet = true
	}
}

// WithAfterGenesis configures the execution to operate in an after-Genesis,
// pre-Chronicle context. Use it when verifying a spend of a UTXO created after
// the Genesis upgrade but before the Chronicle upgrade.
//
// Combined with WithAfterChronicle (in any order), the execution is
// after-Chronicle.
func WithAfterGenesis() ExecutionOptionFunc {
	return func(p *execOpts) {
		p.epochSet = true
		p.flags.AddFlag(scriptflag.UTXOAfterGenesis)
	}
}

// WithAfterChronicle configures the execution to operate in an after-Chronicle
// context. This also implies after-Genesis. Chronicle is the BSV v1.2.0
// protocol upgrade, active on mainnet since April 2026.
//
// This is the default when no epoch is specified (see Engine.Execute), so it
// only needs to be passed explicitly alongside WithFlags, or for clarity.
func WithAfterChronicle() ExecutionOptionFunc {
	return func(p *execOpts) {
		p.epochSet = true
		p.flags.AddFlag(scriptflag.UTXOAfterGenesis)
		p.flags.AddFlag(scriptflag.UTXOAfterChronicle)
	}
}

// WithForkID configure the execution to allow a tx with a fork id.
func WithForkID() ExecutionOptionFunc {
	return func(p *execOpts) {
		p.flags.AddFlag(scriptflag.EnableSighashForkID)
	}
}

// WithP2SH configure the execution to allow a P2SH output.
func WithP2SH() ExecutionOptionFunc {
	return func(p *execOpts) {
		p.flags.AddFlag(scriptflag.Bip16)
	}
}

// WithFlags configure the execution with the provided flags.
//
// The flags are treated as a complete, node-style flag set: the UTXO epoch is
// taken from scriptflag.UTXOAfterGenesis and scriptflag.UTXOAfterChronicle,
// and if neither is set the execution is pre-Genesis, exactly as in the SV
// node. Passing WithFlags therefore disables the after-Chronicle default; add
// WithAfterChronicle (or the UTXO epoch flags) to verify under current rules.
func WithFlags(flags scriptflag.Flag) ExecutionOptionFunc {
	return func(p *execOpts) {
		p.epochSet = true
		p.flags.AddFlag(flags)
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

// WithState inject the provided state into the execution thread. This assumes
// that the state is correct for the scripts provided.
//
// NOTE: This is highly experimental and is unstable when used with unintended states,
// and likely still when used in a happy path scenario. Therefore, it is recommended
// to only be used for debugging purposes.
//
// The safest recommended *interpreter.State records for a given script can be
// are those which can be captured during `debugger.BeforeStep` and `debugger.AfterStep`.
func WithState(state *State) ExecutionOptionFunc {
	return func(p *execOpts) {
		p.state = state
	}
}
