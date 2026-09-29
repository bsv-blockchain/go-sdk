package interpreter

import (
	"context"
	"math"
	"math/big"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	script "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/errs"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// halfOrder is used to tame ECDSA malleability (see BIP0062).
var halfOrder = new(big.Int).Rsh(ec.S256().N, 1)

type thread struct {
	dstack stack // data stack
	astack stack // alt stack
	// stackMem is the memory budget dstack and astack share.
	stackMem stackMemory

	elseStack boolStack

	cfg config

	debug Debugger
	state StateHandler

	scripts         []ParsedScript
	condStack       []int
	savedFirstStack [][]byte // stack from first script for bip16 scripts

	scriptParser OpcodeParser
	scriptIdx    int
	scriptOff    int
	// scriptCodeStart is the parsed index in the current script where the
	// scriptCode begins: just past the most recently executed
	// OP_CODESEPARATOR, or 0 when none has executed -- node's
	// pbegincodehash (interpreter.cpp:407,1445-1448). Storing the start
	// rather than the separator's own index keeps a separator at index 0
	// distinct from no separator at all.
	scriptCodeStart int

	tx         *transaction.Transaction
	inputIdx   int
	prevOutput *transaction.TransactionOutput

	numOps int

	flags scriptflag.Flag
	bip16 bool // treat execution as pay-to-script-hash

	afterGenesis            bool
	afterChronicle          bool
	earlyReturnAfterGenesis bool

	// malleableTxVersion is true when the spending transaction's version
	// allows malleability under Chronicle rules (a signed version above 1).
	malleableTxVersion bool
	// enforceNonMalleability mirrors bitcoin-sv's EnforceNonMalleability:
	// the non-malleability rules (LOW_S, MINIMALDATA, MINIMALIF, NULLFAIL,
	// NULLDUMMY, CLEANSTACK) apply unless the spend is validated under
	// Chronicle rules and the transaction version allows malleability.
	enforceNonMalleability bool

	// ctx is the context.Context passed to WithContext, or nil. ctxDone
	// caches ctx.Done() once so checkContext never calls back into ctx on
	// its hot path: with no context configured (ctx is nil, or its Done()
	// channel is itself nil, as context.Background()'s is) ctxDone is nil,
	// and a nil channel is never ready, so checkContext reduces to a single
	// comparison. Stored rather than threaded through every method thread
	// has (executeOpcode and every opcode implementation among them) because
	// it is set once, by WithContext, for the thread's whole lifetime.
	ctx     context.Context //nolint:containedctx // deliberate: see the comment above
	ctxDone <-chan struct{}

	// stateErr records an error SetState discovers while re-deriving the
	// thread's settings from the injected State. SetState itself has no
	// error to return -- StateHandler is a public interface, and a
	// Debugger can call SetState directly between Step calls, not only
	// through WithState -- so apply (for WithState) and Step each surface
	// it as their own return value the first time they see it.
	stateErr error
}

func createThread(opts *execOpts) (*thread, error) {
	th := &thread{
		scriptParser: &DefaultOpcodeParser{
			ErrorOnCheckSig: opts.tx == nil || opts.previousTxOut == nil,
			nodeExact:       true,
		},
		cfg: &beforeGenesisConfig{},
	}

	if err := th.apply(opts); err != nil {
		return nil, err
	}

	return th, nil
}

// execOpts are the params required for building an Engine
//
// Raw *script.Scripts can be supplied as LockingScript and UnlockingScript, or
// a Tx, an input index, and a previous output.
//
// If checksig operaitons are to be executed without a Tx or a PreviousTxOut supplied,
// the engine will return an ErrInvalidParams on execute.
type execOpts struct {
	lockingScript   *script.Script
	unlockingScript *script.Script
	previousTxOut   *transaction.TransactionOutput
	tx              *transaction.Transaction
	inputIdx        int
	flags           scriptflag.Flag
	// flagsSet records that an option chose the flags (WithFlags or one of
	// the flag options). Without one, Execute enables SIGHASH_FORKID.
	flagsSet bool
	// epochSet records that the caller chose the UTXO epoch, either with an
	// epoch option (WithBeforeGenesis, WithAfterGenesis, WithAfterChronicle,
	// WithGenesis, WithChronicle) or by supplying a full flag set via
	// WithFlags. When false, the execution defaults to after-Chronicle.
	epochSet       bool
	debugger       Debugger
	state          *State
	maxStackMemory int64
	// ctx is set by WithContext. A nil ctx means execution has no work or
	// time budget of its own.
	ctx context.Context //nolint:containedctx // deliberate: carried into thread.ctx, see its own comment
}

func (o execOpts) validate() error {
	// The provided transaction input index must refer to a valid input.
	if o.inputIdx < 0 || (o.tx != nil && o.inputIdx > o.tx.InputCount()-1) {
		return errs.NewError(
			errs.ErrInvalidIndex,
			"transaction input index %d is negative or >= %d", o.inputIdx, len(o.tx.Inputs),
		)
	}

	outputHasLockingScript := o.previousTxOut != nil && o.previousTxOut.LockingScript != nil
	txHasUnlockingScript := o.tx != nil && o.tx.Inputs != nil && len(o.tx.Inputs) > 0 &&
		o.tx.Inputs[o.inputIdx] != nil && o.tx.Inputs[o.inputIdx].UnlockingScript != nil
	// If no locking script was provided
	if o.lockingScript == nil && !outputHasLockingScript {
		return errs.NewError(errs.ErrInvalidParams, "no locking script provided")
	}

	// If no unlocking script was provided
	if o.unlockingScript == nil && !txHasUnlockingScript {
		return errs.NewError(errs.ErrInvalidParams, "no unlocking script provided")
	}

	// If both a locking script and previous output were provided, make sure the scripts match
	if o.lockingScript != nil && outputHasLockingScript {
		if !o.lockingScript.Equals(o.previousTxOut.LockingScript) {
			return errs.NewError(
				errs.ErrInvalidParams,
				"locking script does not match the previous outputs locking script",
			)
		}
	}

	// If both a unlocking script and an input were provided, make sure the scripts match
	if o.unlockingScript != nil && txHasUnlockingScript {
		if !o.unlockingScript.Equals(o.tx.Inputs[o.inputIdx].UnlockingScript) {
			return errs.NewError(
				errs.ErrInvalidParams,
				"unlocking script does not match the unlocking script of the requested input",
			)
		}
	}

	return nil
}

// hasFlag returns whether the script engine instance has the passed flag set.
func (t *thread) hasFlag(flag scriptflag.Flag) bool {
	return t.flags.HasFlag(flag)
}

func (t *thread) hasAny(ff ...scriptflag.Flag) bool {
	return t.flags.HasAny(ff...)
}

func (t *thread) addFlag(flag scriptflag.Flag) {
	t.flags.AddFlag(flag)
}

// checkContextEvery bounds how often a byte-oriented loop whose length a
// script controls (OP_LSHIFT, OP_RSHIFT) calls checkContext: every
// checkContextEvery-th byte rather than every byte, so that with no
// WithContext context (the common case) the loop still pays only a
// once-per-64K-bytes comparison instead of one per byte. It is a plain
// constant rather than a thread field because it bounds only how promptly a
// single long opcode notices ctx is done, not any caller-visible limit.
const (
	checkContextEvery     = 1 << 16
	checkContextEveryMask = checkContextEvery - 1
)

// checkContext reports an errs.ErrExecutionCancelled error, wrapping
// t.ctx.Err(), once the context.Context WithContext supplied is done; nil
// while it is not, and nil always when no context was supplied. It is cheap
// enough to call from a hot loop: with ctxDone nil (no WithContext, or a
// context whose Done() is itself nil) the call is a single comparison;
// otherwise one non-blocking channel receive.
func (t *thread) checkContext() error {
	if t.ctxDone == nil {
		return nil
	}
	select {
	case <-t.ctxDone:
		return errs.NewCancelError(t.ctx.Err())
	default:
		return nil
	}
}

// isBranchExecuting returns whether the current conditional branch is
// actively executing. For example, when the data stack has an OP_FALSE on it
// and an OP_IF is encountered, the branch is inactive until an OP_ELSE or
// OP_ENDIF is encountered.  It properly handles nested conditionals.
func (t *thread) isBranchExecuting() bool {
	return len(t.condStack) == 0 || t.condStack[len(t.condStack)-1] == opCondTrue
}

// executeOpcode performs execution on the passed opcode. It takes into account
// whether it is hidden by conditionals, but some rules still must be
// tested in this case.
func (t *thread) executeOpcode(pop ParsedOpcode) error {
	// An undecodable instruction fails as soon as it is reached, before any
	// other check and whether or not the branch is executing: node's
	// EvalScript fails on GetOp before looking at the opcode
	// (interpreter.cpp:441-451).
	if pop.isMalformed() {
		return pop.op.exec(&pop, t)
	}

	if len(pop.Data) > t.cfg.MaxScriptElementSize() {
		return errs.NewError(errs.ErrElementTooBig,
			"element size %d exceeds max allowed size %d", len(pop.Data), t.cfg.MaxScriptElementSize())
	}

	exec := t.shouldExec(pop)

	// Disabled opcodes are fail on program counter.
	// OP_2MUL and OP_2DIV are re-enabled post-Chronicle.
	if pop.IsDisabled() && (!t.afterGenesis || exec) && !t.afterChronicle {
		return errs.NewError(errs.ErrDisabledOpcode, "attempt to execute disabled opcode %s", pop.Name())
	}

	// Always-illegal opcodes are fail on program counter.
	if pop.AlwaysIllegal() && !t.afterGenesis {
		return errs.NewError(errs.ErrReservedOpcode, "attempt to execute reserved opcode %s", pop.Name())
	}

	// Note that this includes OP_RESERVED which counts as a push operation.
	if pop.op.val > script.Op16 {
		t.numOps++
		if t.numOps > t.cfg.MaxOps() {
			return errs.NewError(errs.ErrTooManyOperations, "exceeded max operation limit of %d", t.cfg.MaxOps())
		}

	}

	if len(pop.Data) > t.cfg.MaxScriptElementSize() {
		return errs.NewError(errs.ErrElementTooBig,
			"element size %d exceeds max allowed size %d", len(pop.Data), t.cfg.MaxScriptElementSize())
	}

	// Nothing left to do when this is not a conditional opcode, and it is
	// not in an executing branch.
	if !t.isBranchExecuting() && !pop.IsConditional() {
		return nil
	}

	// Ensure all executed data push opcodes use the minimal encoding when
	// the minimal data verification flag is set.
	if t.dstack.verifyMinimalData && t.isBranchExecuting() && pop.op.val <= script.OpPUSHDATA4 && exec {
		if err := pop.enforceMinimumDataPush(); err != nil {
			return err
		}
	}

	// If we have already reached an OP_RETURN, we don't execute the next comment, unless it is a conditional,
	// in which case we need to evaluate it as to check for correct if/else balances
	if !exec && !pop.IsConditional() {
		return nil
	}

	err := pop.op.exec(&pop, t)
	// A push the stack memory limit refused (see stack.PushByteArray) is
	// where node's EvalScript stopped with SCRIPT_ERR_STACK_SIZE, so it
	// outranks whatever the rest of the opcode returned.
	if t.stackMem.err != nil {
		return t.stackMem.err
	}
	return err
}

// validPC returns an error if the current script position is valid for
// execution, nil otherwise.
func (t *thread) validPC() error {
	if t.scriptIdx >= len(t.scripts) {
		return errs.NewError(errs.ErrInvalidProgramCounter,
			"past input scripts %v:%v %v:xxxx", t.scriptIdx, t.scriptOff, len(t.scripts))
	}
	if t.scriptOff >= len(t.scripts[t.scriptIdx]) {
		return errs.NewError(errs.ErrInvalidProgramCounter, "past input scripts %v:%v %v:%04d", t.scriptIdx, t.scriptOff,
			t.scriptIdx, len(t.scripts[t.scriptIdx]))
	}
	return nil
}

// CheckErrorCondition returns nil if the running script has ended and was
// successful, leaving a true boolean on the stack.  An error otherwise,
// including if the script has not finished.
func (t *thread) CheckErrorCondition(finalScript bool) error {
	if t.dstack.Depth() < 1 {
		return errs.NewError(errs.ErrEmptyStack, "stack empty at end of script execution")
	}

	if finalScript && t.hasFlag(scriptflag.VerifyCleanStack) && t.enforceNonMalleability && t.dstack.Depth() != 1 {
		return errs.NewError(errs.ErrCleanStack, "stack contains %d unexpected items", t.dstack.Depth()-1)
	}

	v, err := t.dstack.PopBool()
	if err != nil {
		return err
	}
	if !v {
		return errs.NewError(errs.ErrEvalFalse, "false stack entry at end of script execution")
	}

	if finalScript {
		t.afterSuccess()
	}

	return nil
}

func (t *thread) apply(opts *execOpts) error {
	if err := opts.validate(); err != nil {
		return err
	}

	if opts.unlockingScript == nil {
		opts.unlockingScript = opts.tx.Inputs[opts.inputIdx].UnlockingScript
	}
	if opts.lockingScript == nil {
		opts.lockingScript = opts.previousTxOut.LockingScript
	}

	t.ctx = opts.ctx
	if t.ctx != nil {
		t.ctxDone = t.ctx.Done()
	}

	t.tx = opts.tx
	t.flags = opts.flags
	if !opts.flagsSet && opts.flags == 0 {
		// Without any flag option, keep verifying current transactions:
		// every block since the UAHF enables SIGHASH_FORKID.
		t.flags = scriptflag.EnableSighashForkID
	}
	if !opts.epochSet {
		// Chronicle is active on mainnet, so unless the caller names an
		// epoch the execution follows current, after-Chronicle rules.
		t.addFlag(scriptflag.UTXOAfterGenesis | scriptflag.UTXOAfterChronicle)
	}
	t.inputIdx = opts.inputIdx
	t.prevOutput = opts.previousTxOut

	if err := t.applyFlags(); err != nil {
		return err
	}

	t.elseStack = &nopBoolStack{}
	if t.afterGenesis {
		t.elseStack = &stack{debug: &nopDebugger{}, sh: &nopStateHandler{}}
	}

	uscript := opts.unlockingScript
	lscript := opts.lockingScript

	// When both the signature script and public key script are empty the
	// result is necessarily an error since the stack would end up being
	// empty which is equivalent to a false top element.  Thus, just return
	// the relevant error now as an optimization.
	if (uscript == nil || len(*uscript) == 0) && (lscript == nil || len(*lscript) == 0) {
		return errs.NewError(errs.ErrEvalFalse, "false stack entry at end of script execution")
	}

	if err := t.checkCleanStackFlags(); err != nil {
		return err
	}

	if len(*uscript) > t.cfg.MaxScriptSize() {
		return errs.NewError(
			errs.ErrScriptTooBig,
			"unlocking script size %d is larger than the max allowed size %d",
			len(*uscript),
			t.cfg.MaxScriptSize(),
		)
	}
	if len(*lscript) > t.cfg.MaxScriptSize() {
		return errs.NewError(
			errs.ErrScriptTooBig,
			"locking script size %d is larger than the max allowed size %d",
			len(*uscript),
			t.cfg.MaxScriptSize(),
		)
	}

	// The engine stores the scripts in parsed form using a slice.  This
	// allows multiple scripts to be executed in sequence.  For example,
	// with a pay-to-script-hash transaction, there will be ultimately be
	// a third script to execute.
	t.scripts = make([]ParsedScript, 2)
	for i, script := range []*script.Script{uscript, lscript} {
		pscript, err := t.scriptParser.Parse(script)
		if err != nil {
			return err
		}

		t.scripts[i] = pscript
	}

	// Advance the program counter to the public key script if the signature
	// script is empty since there is nothing to execute for it in that
	// case.
	if len(*uscript) == 0 {
		t.scriptIdx++
	}

	// SigPushOnly and Bip16/P2SH -- and the t.bip16 it derives -- depend on
	// the flags and the now-parsed t.scripts, exactly what SetState must
	// also re-derive for a resumed thread, so both call the same helper.
	if err := t.checkParsedScriptFlags(); err != nil {
		return err
	}

	requireMinimal := t.hasFlag(scriptflag.VerifyMinimalData) && t.enforceNonMalleability
	t.dstack = newStack(t.cfg, requireMinimal)
	t.astack = newStack(t.cfg, requireMinimal)
	// The limit is set once any injected state is in place (below), so
	// restoring that state never trips it.
	t.stackMem = stackMemory{limit: math.MaxInt64}
	t.dstack.mem = &t.stackMem
	t.astack.mem = &t.stackMem

	if t.tx != nil && t.prevOutput != nil {
		t.tx.Inputs[t.inputIdx].SetSourceTxOutput(&transaction.TransactionOutput{
			LockingScript: t.prevOutput.LockingScript,
			Satoshis:      t.prevOutput.Satoshis,
		})
	}

	t.state = t
	if opts.debugger == nil {
		opts.debugger = &nopDebugger{}
		t.state = &nopStateHandler{}
	}
	t.debug = opts.debugger
	t.dstack.debug = t.debug
	t.dstack.sh = t.state
	t.astack.debug = t.debug
	t.astack.sh = t.state

	if opts.state != nil {
		t.SetState(opts.state)
		if err := t.stateErr; err != nil {
			t.stateErr = nil
			return err
		}
	}

	// Node limits stack memory only for an output created after Genesis
	// (ConfigScriptPolicy::GetMaxStackMemoryUsage, configscriptpolicy.cpp:139-154);
	// before it the element size and count limits bound the stacks.
	if t.afterGenesis {
		t.stackMem.limit = DefaultMaxStackMemory
		if opts.maxStackMemory > 0 {
			t.stackMem.limit = opts.maxStackMemory
		}
	}

	return nil
}

// applyFlags derives the thread's settings from t.flags: the flags the node
// implies (FORKID forces STRICTENC; the era of the spent output implies the
// era of the spend, and a Chronicle spend is also a Genesis spend), the
// non-malleability gate and the per-era limits.
func (t *thread) applyFlags() error {
	if t.hasFlag(scriptflag.EnableSighashForkID) {
		t.addFlag(scriptflag.VerifyStrictEncoding)
	}

	if t.hasFlag(scriptflag.UTXOAfterChronicle) {
		t.addFlag(scriptflag.Chronicle)
	}
	if t.hasAny(scriptflag.UTXOAfterGenesis, scriptflag.Chronicle) {
		t.addFlag(scriptflag.Genesis)
	}

	// The transaction version is a signed 32-bit value on the wire. Without a
	// transaction the version is taken as 0, which never allows malleability.
	var txVersion int32
	if t.tx != nil {
		txVersion = int32(t.tx.Version) //nolint:gosec // G115 -- nVersion is a signed int32 in consensus
	}
	t.malleableTxVersion = txVersion > 1
	t.enforceNonMalleability = !t.hasFlag(scriptflag.Chronicle) || !t.malleableTxVersion

	t.afterGenesis, t.afterChronicle = false, false
	t.cfg = &beforeGenesisConfig{}
	if t.hasFlag(scriptflag.UTXOAfterGenesis) {
		t.afterGenesis = true
		t.cfg = &afterGenesisConfig{}
	}
	if t.hasFlag(scriptflag.UTXOAfterChronicle) {
		if !t.hasFlag(scriptflag.UTXOAfterGenesis) {
			return errs.NewError(errs.ErrInvalidFlags, "UTXOAfterChronicle requires UTXOAfterGenesis")
		}
		t.afterChronicle = true
		t.cfg = &afterChronicleConfig{}
	}
	return nil
}

// checkCleanStackFlags reports errs.ErrInvalidFlags when the clean stack
// flag (ScriptVerifyCleanStack) is set without pay-to-script-hash
// evaluation (ScriptBip16).
//
// Recall that evaluating a P2SH script without the flag set results in
// non-P2SH evaluation which leaves the P2SH inputs on the stack. Thus,
// allowing the clean stack flag without the P2SH flag would make it
// possible to have a situation where P2SH would not be a soft fork when it
// should be.
//
// Depends only on t.flags, so apply() and SetState call it identically.
func (t *thread) checkCleanStackFlags() error {
	if t.hasFlag(scriptflag.VerifyCleanStack) && !t.hasFlag(scriptflag.Bip16) {
		return errs.NewError(errs.ErrInvalidFlags, "invalid scriptflag combination")
	}
	return nil
}

// checkParsedScriptFlags applies the two checks apply() runs once both
// scripts are parsed, and derives t.bip16 -- the one piece of thread state,
// besides t.flags, t.scripts and the era/malleability fields applyFlags
// already covers, that a flag word together with the parsed scripts
// determines. SetState calls it too, right after re-deriving everything
// else, so a resumed thread enforces exactly what a one-shot run with the
// same State().Flags and State().Scripts would; keeping this logic in one
// place is what makes that guarantee possible to keep true. The relative
// order of the two checks matches apply()'s for a one-shot run's error
// precedence.
func (t *thread) checkParsedScriptFlags() error {
	if len(t.scripts) < 2 {
		return errs.NewError(errs.ErrInvalidParams,
			"need an unlocking and a locking script, got %d", len(t.scripts))
	}

	// The signature script must only contain data pushes when the
	// associated flag is set and the spend is either post-Genesis but
	// pre-Chronicle, or post-Chronicle with a non-malleable transaction
	// version.
	if t.hasFlag(scriptflag.VerifySigPushOnly) && !t.scripts[0].IsPushOnly() {
		chronicle := t.hasFlag(scriptflag.Chronicle)
		if (t.hasFlag(scriptflag.Genesis) && !chronicle) || (chronicle && !t.malleableTxVersion) {
			return errs.NewError(errs.ErrNotPushOnly, "signature script is not push only")
		}
	}

	// Pay-to-script-hash is only evaluated for outputs created before
	// Genesis.
	t.bip16 = false
	if t.hasFlag(scriptflag.Bip16) && !t.afterGenesis && t.scripts[1].isP2SH() {
		// Only accept input scripts that push data for P2SH.
		if !t.scripts[0].IsPushOnly() {
			return errs.NewError(errs.ErrNotPushOnly, "pay to script hash is not push only")
		}
		t.bip16 = true
	}

	return nil
}

func (t *thread) execute() error {
	// Checked once up front so an already-done context.Context is rejected
	// before the first opcode, rather than only once Step's own check runs.
	if err := t.checkContext(); err != nil {
		return err
	}

	if err := func() error {
		defer t.afterExecute()
		t.beforeExecute()
		for {
			t.beforeStep()

			done, err := t.Step()
			if err != nil {
				return err
			}

			t.afterStep()
			if done {
				return nil
			}
		}
	}(); err != nil {
		return err
	}

	return t.CheckErrorCondition(true)
}

// Step will execute the next instruction and move the program counter to the
// next opcode in the script, or the next script if the current has ended.  Step
// will return true in the case that the last opcode was successfully executed.
//
// The result of calling Step or any other method is undefined if an error is
// returned.
func (t *thread) Step() (bool, error) {
	// A SetState call since the last Step -- whether through WithState's
	// one call in apply, or a Debugger driving the thread directly -- may
	// have left an error on the thread; see stateErr's own doc.
	if err := t.stateErr; err != nil {
		t.stateErr = nil
		return true, err
	}

	// Checked before decoding or executing anything else this step, as
	// node's EvalScript checks its cancellation token at the top of its
	// opcode loop (interpreter.cpp:441-445).
	if err := t.checkContext(); err != nil {
		return true, err
	}

	// Verify that it is pointing to a valid script address.
	if err := t.validPC(); err != nil {
		return true, err
	}

	opcode := t.scripts[t.scriptIdx][t.scriptOff]

	t.beforeExecuteOpcode()
	// Execute the opcode while taking into account several things such as
	// disabled opcodes, illegal opcodes, maximum allowed operations per
	// script, maximum script element sizes, and conditionals.
	if err := t.executeOpcode(opcode); err != nil {
		if !errs.IsErrorCode(err, errs.ErrOK) {
			return true, err
		}

		// A top-level OP_RETURN after Genesis ends the current script
		// successfully: node's EvalScript returns SCRIPT_ERR_OK
		// (interpreter.cpp:856-862) and VerifyScript goes on to the next
		// script exactly as if this one had run to its end.
		t.afterExecuteOpcode()
		return t.endOfScript()
	}
	t.afterExecuteOpcode()

	t.scriptOff++

	// The number of elements in the combination of the data and alt stacks
	// must not exceed the maximum number of stack elements allowed.
	combinedStackSize := t.dstack.Depth() + t.astack.Depth()
	if combinedStackSize > int32(t.cfg.MaxStackSize()) { //nolint:gosec // G115 -- configured max stack size is a small constant well within int32
		return false, errs.NewError(errs.ErrStackOverflow,
			"combined stack size %d > max allowed %d", combinedStackSize, t.cfg.MaxStackSize())
	}

	if t.scriptOff < len(t.scripts[t.scriptIdx]) {
		return false, nil
	}

	return t.endOfScript()
}

// endOfScript finishes the current script and prepares the next one, and
// reports whether every script has now run. Node runs each script in its own
// EvalScript call, so the alt stack, the OP_CODESEPARATOR position, the op
// count and the conditional state never carry over from one script to the
// next; only the data stack does (interpreter.cpp:407,1993-1995 and
// VerifyScript, 2338-2372).
func (t *thread) endOfScript() (bool, error) {
	// Illegal to have an `if' that straddles two scripts.
	if len(t.condStack) != 0 {
		return false, errs.NewError(errs.ErrUnbalancedConditional, "end of script reached in conditional execution")
	}

	// Alt stack doesn't persist. Its memory does: node's alt stack is a child
	// LimitedStack made for each EvalScript call (interpreter.cpp:1993) and
	// destroyed at its end without handing its elements' bytes back to the
	// parent (script/limitedstack.h declares no destructor), so whatever was
	// left on it keeps counting against the limit for the rest of the spend.
	used := t.stackMem.used
	_ = t.astack.DropN(t.astack.Depth())
	t.stackMem.used = used

	// Move onto the next script
	t.shiftScript()

	if t.bip16 && !t.afterGenesis && t.scriptIdx <= 2 {
		switch t.scriptIdx {
		case 1:
			t.savedFirstStack = t.GetStack()
		case 2:
			// Put us past the end for CheckErrorCondition()
			// Check script ran successfully and pull the script
			// out of the first stack and execute that.
			if err := t.CheckErrorCondition(false); err != nil {
				return false, err
			}

			scr := t.savedFirstStack[len(t.savedFirstStack)-1]
			pops, err := t.scriptParser.Parse(script.NewFromBytes(scr))
			if err != nil {
				return false, err
			}

			t.scripts = append(t.scripts, pops)

			// Set stack to be the stack from first script minus the
			// script itself
			t.SetStack(t.savedFirstStack[:len(t.savedFirstStack)-1])
		}
	}

	// there are zero length scripts in the wild
	if t.scriptIdx < len(t.scripts) && t.scriptOff >= len(t.scripts[t.scriptIdx]) {
		t.scriptIdx++
	}

	return t.scriptIdx >= len(t.scripts), nil
}

// GetStack returns the contents of the primary stack as an array. where the
// last item in the array is the top of the stack.
func (t *thread) GetStack() [][]byte {
	return getStack(&t.dstack)
}

// SetStack sets the contents of the primary stack to the contents of the
// provided array where the last item in the array will be the top of the stack.
func (t *thread) SetStack(data [][]byte) {
	setStack(&t.dstack, data)
}

// subScript returns the script since the last executed OP_CODESEPARATOR
// (node's scriptCode {pbegincodehash, pend}, interpreter.cpp:1445-1448,1473).
func (t *thread) subScript() ParsedScript {
	return t.scripts[t.scriptIdx][t.scriptCodeStart:]
}

// checkHashTypeEncoding returns whether the passed hashtype adheres to
// the strict encoding requirements if enabled. It mirrors bitcoin-sv's
// CheckSignatureEncoding STRICTENC block (interpreter.cpp:291-306).
func (t *thread) checkHashTypeEncoding(shf sighash.Flag) error {
	if !t.hasFlag(scriptflag.VerifyStrictEncoding) {
		return nil
	}

	sigHashType := shf & ^sighash.AnyOneCanPay
	if t.hasFlag(scriptflag.VerifyBip143SigHash) {
		// scriptflag.VerifyBip143SigHash is a non-consensus, ts-stack/
		// bitcoin-abc conformance-only knob (see scriptflag.go doc): no
		// node flag word ever sets it, and it reuses bit 0x20 for an
		// unrelated legacy purpose, so it is deliberately exempt from the
		// Chronicle handling below -- keep its pre-existing behavior of
		// checking only definedness once the ForkID bit is forced off.
		sigHashType ^= sighash.ForkID
		if shf&sighash.ForkID == 0 {
			return errs.NewError(errs.ErrInvalidSigHashType, "hash type does not contain uahf forkID 0x%x", uint8(shf))
		}
		if sigHashType < sighash.All || sigHashType > sighash.Single {
			return errs.NewError(errs.ErrInvalidSigHashType, "invalid hash type 0x%x", uint8(shf))
		}
		return nil
	}

	// SigHashType::isDefined (script/sighashtype.h) masks out ForkID,
	// AnyOneCanPay (already removed above) and Chronicle before requiring
	// the remaining base type to be ALL/NONE/SINGLE -- a Chronicle-bit hash
	// type (0x20-0x23, 0x60-0x63, ...) is therefore always "defined",
	// independent of whether Chronicle is enabled for this spend.
	baseType := sigHashType &^ sighash.ForkID &^ sighash.Chronicle
	if baseType < sighash.All || baseType > sighash.Single {
		return errs.NewError(errs.ErrInvalidSigHashType, "invalid hash type 0x%x", uint8(shf))
	}

	// interpreter.cpp:296-305, in this exact order: a hash type may not
	// claim a fork/era the spend is not validated under, and once ForkID is
	// enabled every signature must use it.
	forkIDEnabled := t.hasFlag(scriptflag.EnableSighashForkID)
	chronicleEnabled := t.hasFlag(scriptflag.Chronicle)
	usesForkID := shf.Has(sighash.ForkID)
	usesChronicle := shf.Has(sighash.Chronicle)
	if !forkIDEnabled && usesForkID {
		return errs.NewError(errs.ErrIllegalForkID, "fork id sighash set without flag")
	}
	if !chronicleEnabled && usesChronicle {
		return errs.NewError(errs.ErrIllegalChronicle, "chronicle sighash set without flag")
	}
	if forkIDEnabled && !usesForkID {
		return errs.NewError(errs.ErrMustUseForkID, "signature must use SIGHASH_FORKID")
	}

	return nil
}

// checkPubKeyEncoding returns whether the passed public key adheres to
// the strict encoding requirements if enabled.
func (t *thread) checkPubKeyEncoding(pubKey []byte) error {
	if !t.hasFlag(scriptflag.VerifyStrictEncoding) {
		return nil
	}

	if len(pubKey) == 33 && (pubKey[0] == 0x02 || pubKey[0] == 0x03) {
		// Compressed
		return nil
	}
	if len(pubKey) == 65 && pubKey[0] == 0x04 {
		// Uncompressed
		return nil
	}

	return errs.NewError(errs.ErrPubKeyType, "unsupported public key type")
}

// checkSignatureEncoding returns whether the passed signature adheres to
// the strict encoding requirements if enabled.
func (t *thread) checkSignatureEncoding(sig []byte) error {
	if !t.hasAny(scriptflag.VerifyDERSignatures, scriptflag.VerifyLowS, scriptflag.VerifyStrictEncoding) {
		return nil
	}

	// The format of a DER encoded signature is as follows:
	//
	// 0x30 <total length> 0x02 <length of R> <R> 0x02 <length of S> <S>
	//   - 0x30 is the ASN.1 identifier for a sequence
	//   - Total length is 1 byte and specifies length of all remaining data
	//   - 0x02 is the ASN.1 identifier that specifies an integer follows
	//   - Length of R is 1 byte and specifies how many bytes R occupies
	//   - R is the arbitrary length big-endian encoded number which
	//     represents the R value of the signature.  DER encoding dictates
	//     that the value must be encoded using the minimum possible number
	//     of bytes.  This implies the first byte can only be null if the
	//     highest bit of the next byte is set in order to prevent it from
	//     being interpreted as a negative number.
	//   - 0x02 is once again the ASN.1 integer identifier
	//   - Length of S is 1 byte and specifies how many bytes S occupies
	//   - S is the arbitrary length big-endian encoded number which
	//     represents the S value of the signature.  The encoding rules are
	//     identical as those for R.
	const (
		asn1SequenceID = 0x30
		asn1IntegerID  = 0x02

		// minSigLen is the minimum length of a DER encoded signature and is
		// when both R and S are 1 byte each.
		//
		// 0x30 + <1-byte> + 0x02 + 0x01 + <byte> + 0x2 + 0x01 + <byte>
		minSigLen = 8

		// maxSigLen is the maximum length of a DER encoded signature and is
		// when both R and S are 33 bytes each.  It is 33 bytes because a
		// 256-bit integer requires 32 bytes and an additional leading null byte
		// might be required if the high bit is set in the value.
		//
		// 0x30 + <1-byte> + 0x02 + 0x21 + <33 bytes> + 0x2 + 0x21 + <33 bytes>
		maxSigLen = 72

		// sequenceOffset is the byte offset within the signature of the
		// expected ASN.1 sequence identifier.
		sequenceOffset = 0

		// dataLenOffset is the byte offset within the signature of the expected
		// total length of all remaining data in the signature.
		dataLenOffset = 1

		// rTypeOffset is the byte offset within the signature of the ASN.1
		// identifier for R and is expected to indicate an ASN.1 integer.
		rTypeOffset = 2

		// rLenOffset is the byte offset within the signature of the length of
		// R.
		rLenOffset = 3

		// rOffset is the byte offset within the signature of R.
		rOffset = 4
	)

	// The signature must adhere to the minimum and maximum allowed length.
	sigLen := len(sig)
	if sigLen < minSigLen {
		return errs.NewError(errs.ErrSigTooShort, "malformed signature: too short: %d < %d", sigLen, minSigLen)
	}
	if sigLen > maxSigLen {
		return errs.NewError(errs.ErrSigTooLong, "malformed signature: too long: %d > %d", sigLen, maxSigLen)
	}

	// The signature must start with the ASN.1 sequence identifier.
	if sig[sequenceOffset] != asn1SequenceID {
		return errs.NewError(errs.ErrSigInvalidSeqID, "malformed signature: format has wrong type: %#x", sig[sequenceOffset])
	}

	// The signature must indicate the correct amount of data for all elements
	// related to R and S.
	if int(sig[dataLenOffset]) != sigLen-2 {
		return errs.NewError(
			errs.ErrSigInvalidDataLen,
			"malformed signature: bad length: %d != %d",
			sig[dataLenOffset], sigLen-2,
		)
	}

	// Calculate the offsets of the elements related to S and ensure S is inside
	// the signature.
	//
	// rLen specifies the length of the big-endian encoded number which
	// represents the R value of the signature.
	//
	// sTypeOffset is the offset of the ASN.1 identifier for S and, like its R
	// counterpart, is expected to indicate an ASN.1 integer.
	//
	// sLenOffset and sOffset are the byte offsets within the signature of the
	// length of S and S itself, respectively.
	rLen := int(sig[rLenOffset])
	sTypeOffset := rOffset + rLen
	sLenOffset := sTypeOffset + 1
	if sTypeOffset >= sigLen {
		return errs.NewError(errs.ErrSigMissingSTypeID, "malformed signature: S type indicator missing")
	}
	if sLenOffset >= sigLen {
		return errs.NewError(errs.ErrSigMissingSLen, "malformed signature: S length missing")
	}

	// The lengths of R and S must match the overall length of the signature.
	//
	// sLen specifies the length of the big-endian encoded number which
	// represents the S value of the signature.
	sOffset := sLenOffset + 1
	sLen := int(sig[sLenOffset])
	if sOffset+sLen != sigLen {
		return errs.NewError(errs.ErrSigInvalidSLen, "malformed signature: invalid S length")
	}

	// R elements must be ASN.1 integers.
	if sig[rTypeOffset] != asn1IntegerID {
		return errs.NewError(errs.ErrSigInvalidRIntID,
			"malformed signature: R integer marker: %#x != %#x", sig[rTypeOffset], asn1IntegerID)
	}

	// Zero-length integers are not allowed for R.
	if rLen == 0 {
		return errs.NewError(errs.ErrSigZeroRLen, "malformed signature: R length is zero")
	}

	// R must not be negative.
	if sig[rOffset]&0x80 != 0 {
		return errs.NewError(errs.ErrSigNegativeR, "malformed signature: R is negative")
	}

	// Null bytes at the start of R are not allowed, unless R would otherwise be
	// interpreted as a negative number.
	if rLen > 1 && sig[rOffset] == 0x00 && sig[rOffset+1]&0x80 == 0 {
		return errs.NewError(errs.ErrSigTooMuchRPadding, "malformed signature: R value has too much padding")
	}

	// S elements must be ASN.1 integers.
	if sig[sTypeOffset] != asn1IntegerID {
		return errs.NewError(errs.ErrSigInvalidSIntID,
			"malformed signature: S integer marker: %#x != %#x", sig[sTypeOffset], asn1IntegerID)
	}

	// Zero-length integers are not allowed for S.
	if sLen == 0 {
		return errs.NewError(errs.ErrSigZeroSLen, "malformed signature: S length is zero")
	}

	// S must not be negative.
	if sig[sOffset]&0x80 != 0 {
		return errs.NewError(errs.ErrSigNegativeS, "malformed signature: S is negative")
	}

	// Null bytes at the start of S are not allowed, unless S would otherwise be
	// interpreted as a negative number.
	if sLen > 1 && sig[sOffset] == 0x00 && sig[sOffset+1]&0x80 == 0 {
		return errs.NewError(errs.ErrSigTooMuchSPadding, "malformed signature: S value has too much padding")
	}

	// Verify the S value is <= half the order of the curve.  This check is done
	// because when it is higher, the complement modulo the order can be used
	// instead which is a shorter encoding by 1 byte.  Further, without
	// enforcing this, it is possible to replace a signature in a valid
	// transaction with the complement while still being a valid signature that
	// verifies.  This would result in changing the transaction hash and thus is
	// a source of malleability.
	//
	// Node's CPubKey::CheckLowS (pubkey.cpp:353-363) judges S after its lax
	// parse, where an R or S >= N overflows to the all-zero signature, whose
	// S is not high.
	if t.hasFlag(scriptflag.VerifyLowS) && t.enforceNonMalleability {
		if _, sValue, ok := parseSignatureLax(sig); !ok || sValue.Cmp(halfOrder) > 0 {
			return errs.NewError(errs.ErrSigHighS, "signature is not canonical due to unnecessarily high S value")
		}
	}
	return nil
}

// getStack returns the contents of stack as a byte array bottom up
func getStack(stack *stack) [][]byte {
	array := make([][]byte, stack.Depth())
	for i := range array {
		// PeekByteArray can't fail due to overflow, already checked
		array[len(array)-i-1], _ = stack.PeekByteArray(int32(i))
	}
	return array
}

// setStack sets the stack to the contents of the array where the last item in
// the array is the top item in the stack.
func setStack(stack *stack, data [][]byte) {
	// This can not error. Only errors are for invalid arguments.
	_ = stack.DropN(stack.Depth())

	for i := range data {
		stack.PushByteArray(data[i])
	}
}

// shouldExec returns true if the engine should execute the passed in operation,
// based on its own internal state.
func (t *thread) shouldExec(pop ParsedOpcode) bool {
	if !t.afterGenesis {
		return true
	}
	cf := true
	for _, v := range t.condStack {
		if v == opCondFalse {
			cf = false
			break
		}
	}

	return cf && (!t.earlyReturnAfterGenesis || pop.op.val == script.OpRETURN)
}

func (t *thread) shiftScript() {
	defer t.afterScriptChange()
	t.beforeScriptChange()

	t.numOps = 0
	t.scriptOff = 0
	t.scriptIdx++
	t.earlyReturnAfterGenesis = false
	t.scriptCodeStart = 0
}

func (t *thread) beforeExecute() {
	t.debug.BeforeExecute(t.state.State())
}

func (t *thread) afterExecute() {
	t.debug.AfterExecute(t.state.State())
}

func (t *thread) beforeStep() {
	t.debug.BeforeStep(t.state.State())
}

func (t *thread) afterStep() {
	t.debug.AfterStep(t.state.State())
}

func (t *thread) beforeExecuteOpcode() {
	t.debug.BeforeExecuteOpcode(t.state.State())
}

func (t *thread) afterExecuteOpcode() {
	t.debug.AfterExecuteOpcode(t.state.State())
}

func (t *thread) beforeScriptChange() {
	t.debug.BeforeScriptChange(t.state.State())
}

func (t *thread) afterScriptChange() {
	t.debug.AfterScriptChange(t.state.State())
}

func (t *thread) afterError(err error) {
	t.debug.AfterError(t.state.State(), err)
}

func (t *thread) afterSuccess() {
	t.debug.AfterSuccess(t.state.State())
}

// subScriptForChecksig returns the scriptCode used by OP_CHECKSIG and
// OP_CHECKMULTISIG: the script since the last OP_CODESEPARATOR (subScript),
// with the full locking (prevout) script appended when a Chronicle-era
// CHECKSIG/CHECKMULTISIG is executing directly inside the unlocking script.
//
// This mirrors bitcoin-sv's checksigData/IsChronicle(flags) append
// (interpreter.cpp:1471-1481 for OP_CHECKSIG, :1568-1578 for
// OP_CHECKMULTISIG), fed by VerifyScript's checksigData argument: it is set
// to &scriptPubKey only for the raw unlocking script's own EvalScript call,
// and left nil for the locking script and for a P2SH redeem script
// (interpreter.cpp:2338 vs 2358/2402). scriptIdx 0 is always that raw
// unlocking script -- never the locking script (index 1) or a P2SH redeem
// script (index 2) -- so checking it alone reproduces that distinction.
func (t *thread) subScriptForChecksig() ParsedScript {
	scr := t.subScript()
	if t.scriptIdx != 0 || !t.hasFlag(scriptflag.Chronicle) {
		return scr
	}

	// Node decodes the joined bytes as one script. When the unlocking
	// script ends in an undecodable instruction (reachable past a top-level
	// OP_RETURN), that instruction runs on into the locking script, so the
	// joined bytes are decoded again from there instead of appending the
	// separately parsed locking script: FindAndDelete and the legacy
	// digest's OP_CODESEPARATOR removal then see the instructions node sees.
	if n := len(scr); n > 0 && scr[n-1].isMalformed() {
		if tail, err := reparseJoined(scr[n-1].Data, t.scripts[1]); err == nil {
			full := make(ParsedScript, 0, n-1+len(tail))
			full = append(full, scr[:n-1]...)
			return append(full, tail...)
		}
	}

	full := make(ParsedScript, 0, len(scr)+len(t.scripts[1]))
	full = append(full, scr...)
	full = append(full, t.scripts[1]...)
	return full
}

// reparseJoined decodes head followed by the bytes of pscr as a single
// script. The parser is used through the OpcodeParser interface: calling
// DefaultOpcodeParser.Parse directly from here would make opcodeArray's
// initialization depend on itself (via opcodeCheckSig).
func reparseJoined(head []byte, pscr ParsedScript) (ParsedScript, error) {
	var parser OpcodeParser = &DefaultOpcodeParser{nodeExact: true}
	raw, err := parser.Unparse(pscr)
	if err != nil {
		return nil, err
	}
	joined := make([]byte, 0, len(head)+len(*raw))
	joined = append(append(joined, head...), *raw...)
	return parser.Parse(script.NewFromBytes(joined))
}
