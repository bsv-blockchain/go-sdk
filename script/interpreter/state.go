package interpreter

import "github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"

// State a snapshot of a threads state during execution.
type State struct {
	DataStack       [][]byte
	AltStack        [][]byte
	ElseStack       [][]byte
	CondStack       []int
	SavedFirstStack [][]byte
	Scripts         []ParsedScript
	ScriptIdx       int
	OpcodeIdx       int
	// LastCodeSeparatorIdx is the index of the last executed OP_CODESEPARATOR
	// in the current script, or 0 if none was executed. It cannot tell a
	// separator at index 0 from none; SetState prefers ScriptCodeStart.
	LastCodeSeparatorIdx int
	// ScriptCodeStart is the index in the current script where the
	// scriptCode signed by CHECKSIG starts: one past the last executed
	// OP_CODESEPARATOR, or 0 if none was executed.
	ScriptCodeStart int
	// StackMemory is the stack memory counted against the limit set with
	// WithMaxStackMemory: each element on the data and alt stacks plus 32
	// bytes each, and whatever an earlier script left on the alt stack.
	// SetState counts at least the elements of DataStack and AltStack.
	StackMemory int64
	NumOps      int
	Flags       scriptflag.Flag
	IsFinished  bool
	Genesis     struct {
		AfterGenesis bool
		EarlyReturn  bool
	}
}

// Opcode the current interpreter.ParsedOpcode from the
// threads program counter.
func (s *State) Opcode() ParsedOpcode {
	return s.Scripts[s.ScriptIdx][s.OpcodeIdx]
}

// RemainingScript the remaining script to be executed.
func (s *State) RemainingScript() ParsedScript {
	return s.Scripts[s.ScriptIdx][s.OpcodeIdx:]
}

// StateHandler interfaces getting and applying state.
type StateHandler interface {
	State() *State
	SetState(state *State)
}

type nopStateHandler struct{}

func (n *nopStateHandler) State() *State {
	return &State{}
}
func (n *nopStateHandler) SetState(state *State) {}

func (t *thread) State() *State {
	scriptIdx := t.scriptIdx
	offsetIdx := t.scriptOff
	if scriptIdx >= len(t.scripts) {
		scriptIdx = len(t.scripts) - 1
		offsetIdx = len(t.scripts[scriptIdx]) - 1
	}

	if offsetIdx >= len(t.scripts[scriptIdx]) {
		offsetIdx = len(t.scripts[scriptIdx]) - 1
	}
	ts := State{
		DataStack:            make([][]byte, int(t.dstack.Depth())),
		AltStack:             make([][]byte, int(t.astack.Depth())),
		ElseStack:            make([][]byte, int(t.elseStack.Depth())),
		CondStack:            make([]int, len(t.condStack)),
		SavedFirstStack:      make([][]byte, len(t.savedFirstStack)),
		Scripts:              make([]ParsedScript, len(t.scripts)),
		ScriptIdx:            scriptIdx,
		OpcodeIdx:            offsetIdx,
		LastCodeSeparatorIdx: max(t.scriptCodeStart-1, 0),
		ScriptCodeStart:      t.scriptCodeStart,
		StackMemory:          t.stackMem.used,
		NumOps:               t.numOps,
		Flags:                t.flags,
		IsFinished:           t.scriptIdx > scriptIdx,
		Genesis: struct {
			AfterGenesis bool
			EarlyReturn  bool
		}{
			AfterGenesis: t.afterGenesis,
			EarlyReturn:  t.earlyReturnAfterGenesis,
		},
	}

	for i, dd := range t.dstack.stk {
		ts.DataStack[i] = make([]byte, len(dd))
		copy(ts.DataStack[i], dd)
	}

	for i, aa := range t.astack.stk {
		ts.AltStack[i] = make([]byte, len(aa))
		copy(ts.AltStack[i], aa)
	}

	if stk, ok := t.elseStack.(*stack); ok {
		for i, ee := range stk.stk {
			ts.ElseStack[i] = make([]byte, len(ee))
			copy(ts.ElseStack[i], ee)
		}
	}

	for i, ss := range t.savedFirstStack {
		ts.SavedFirstStack[i] = make([]byte, len(ss))
		copy(ts.SavedFirstStack[i], ss)
	}

	copy(ts.CondStack, t.condStack)

	for i, script := range t.scripts {
		ts.Scripts[i] = make(ParsedScript, len(script))
		copy(ts.Scripts[i], script)
	}

	return &ts
}

func (t *thread) SetState(state *State) {
	setStack(&t.dstack, state.DataStack)
	setStack(&t.astack, state.AltStack)
	var counted int64
	for _, stk := range [][][]byte{state.DataStack, state.AltStack} {
		for _, b := range stk {
			counted += int64(len(b)) + stackElementOverhead
		}
	}
	t.stackMem.used = max(state.StackMemory, counted)
	t.stackMem.err = nil
	t.condStack = make([]int, len(state.CondStack))
	copy(t.condStack, state.CondStack)
	t.savedFirstStack = state.SavedFirstStack

	t.scripts = state.Scripts
	t.scriptIdx = state.ScriptIdx
	t.scriptOff = state.OpcodeIdx
	switch {
	case state.ScriptCodeStart > 0:
		t.scriptCodeStart = state.ScriptCodeStart
	case state.LastCodeSeparatorIdx > 0:
		t.scriptCodeStart = state.LastCodeSeparatorIdx + 1
	default:
		t.scriptCodeStart = 0
	}
	t.numOps = state.NumOps
	t.earlyReturnAfterGenesis = state.Genesis.EarlyReturn

	// Re-derive everything the flags decide, so the resumed thread runs
	// under the rules State().Flags reports. A State from State() always has
	// valid flags; an invalid combination is an error, and the thread keeps
	// its current settings.
	previous := t.flags
	t.flags = state.Flags
	flagsErr := t.applyFlags()
	if flagsErr != nil {
		t.flags = previous
		_ = t.applyFlags()
	}
	if state.Genesis.AfterGenesis && !t.afterGenesis {
		t.afterGenesis = true
		t.cfg = &afterGenesisConfig{}
	}
	t.elseStack = &nopBoolStack{}
	if t.afterGenesis {
		es := &stack{debug: &nopDebugger{}, sh: &nopStateHandler{}}
		setStack(es, state.ElseStack)
		t.elseStack = es
	}
	requireMinimal := t.hasFlag(scriptflag.VerifyMinimalData) && t.enforceNonMalleability
	for _, s := range []*stack{&t.dstack, &t.astack} {
		s.verifyMinimalData = requireMinimal
		s.maxNumLength = t.cfg.MaxScriptNumberLength()
		s.afterGenesis = t.cfg.AfterGenesis()
	}

	// Re-derive the checks apply() runs on the flags and the parsed
	// scripts, including whether the spend is evaluated as P2SH (t.bip16).
	// SetState cannot return an error (StateHandler is a public
	// interface), so apply and Step return stateErr instead.
	t.stateErr = flagsErr
	if t.stateErr == nil {
		t.stateErr = t.checkCleanStackFlags()
	}
	if t.stateErr == nil {
		t.stateErr = t.checkParsedScriptFlags()
	}
}
