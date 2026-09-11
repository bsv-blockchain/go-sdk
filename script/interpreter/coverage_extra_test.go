package interpreter

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
)

// TestNopDebugger exercises every method on the no-op debugger so that the
// default (undebugged) execution path's helper type is fully covered.
func TestNopDebugger(t *testing.T) {
	t.Parallel()

	d := &nopDebugger{}
	st := &State{}

	require.NotPanics(t, func() {
		d.BeforeExecute(st)
		d.AfterExecute(st)
		d.BeforeStep(st)
		d.AfterStep(st)
		d.BeforeExecuteOpcode(st)
		d.AfterExecuteOpcode(st)
		d.BeforeScriptChange(st)
		d.AfterScriptChange(st)
		d.BeforeStackPush(st, []byte{0x01})
		d.AfterStackPush(st, []byte{0x01})
		d.BeforeStackPop(st)
		d.AfterStackPop(st, []byte{0x01})
		d.AfterSuccess(st)
		d.AfterError(st, nil)
	})
}

// TestNopStateHandler covers the no-op state handler helpers.
func TestNopStateHandler(t *testing.T) {
	t.Parallel()

	h := &nopStateHandler{}
	require.NotNil(t, h.State())
	require.NotPanics(t, func() {
		h.SetState(&State{})
	})
}

// TestNopBoolStack covers the no-op bool stack helper methods.
func TestNopBoolStack(t *testing.T) {
	t.Parallel()

	n := &nopBoolStack{}
	n.PushBool(true)

	b, err := n.PeekBool(0)
	require.NoError(t, err)
	require.False(t, b)

	require.Equal(t, int32(0), n.Depth())
}

// TestStackString covers the String rendering of a stack, both with populated
// and empty entries.
func TestStackString(t *testing.T) {
	t.Parallel()

	s := &stack{debug: &nopDebugger{}, sh: &nopStateHandler{}}
	s.PushByteArray([]byte{0xde, 0xad})
	s.PushByteArray(nil) // empty entry exercises the <empty> branch

	out := s.String()
	require.Contains(t, out, "<empty>")
	require.NotEmpty(t, out)
}

// TestParsedOpcodeValueLength covers ParsedOpcode.Value and ParsedOpcode.Length.
func TestParsedOpcodeValueLength(t *testing.T) {
	t.Parallel()

	scr := &script.Script{}
	require.NoError(t, scr.AppendOpcodes(script.Op1))

	var parser DefaultOpcodeParser
	parsed, err := parser.Parse(scr)
	require.NoError(t, err)
	require.Len(t, parsed, 1)

	require.Equal(t, script.Op1, parsed[0].Value())
	require.Equal(t, 1, parsed[0].Length())
}

// TestExecOptionsExtra covers WithP2SH and WithDebugger option setters.
func TestExecOptionsExtra(t *testing.T) {
	t.Parallel()

	t.Run("WithP2SH sets Bip16", func(t *testing.T) {
		t.Parallel()
		opts := &execOpts{}
		WithP2SH()(opts)
		require.True(t, opts.flags.HasFlag(scriptflag.Bip16))
	})

	t.Run("WithDebugger sets debugger", func(t *testing.T) {
		t.Parallel()
		opts := &execOpts{}
		d := &nopDebugger{}
		WithDebugger(d)(opts)
		require.Equal(t, d, opts.debugger)
	})
}

// TestConfigExtra covers the config accessors that are not otherwise exercised.
func TestConfigExtra(t *testing.T) {
	t.Parallel()

	require.False(t, (&afterGenesisConfig{}).AfterChronicle())
	require.False(t, (&beforeGenesisConfig{}).AfterChronicle())
	require.Equal(t, math.MaxInt32, (&afterChronicleConfig{}).MaxPubKeysPerMultiSig())
}

// captureDebugger records that state accessors are reachable during a real
// execution driven through WithDebugger. It embeds the Debugger interface so
// only the callbacks of interest need overriding.
type captureDebugger struct {
	Debugger

	sawOpcode bool
	steps     int
}

func (c *captureDebugger) BeforeExecuteOpcode(s *State) {
	c.steps++
	if len(s.RemainingScript()) > 0 {
		// Opcode reads Scripts[ScriptIdx][OpcodeIdx]; the thread clamps the
		// indices so this is always a valid access mid-execution.
		_ = s.Opcode()
		c.sawOpcode = true
	}
}

// TestEngineWithDebuggerState drives a real (successful) execution with a
// debugger installed. This exercises thread.State, State.Opcode and
// State.RemainingScript via the live state-cloning path.
func TestEngineWithDebuggerState(t *testing.T) {
	t.Parallel()

	uscript, err := script.NewFromHex("52") // OP_2
	require.NoError(t, err)
	lscript, err := script.NewFromHex("5287") // OP_2 OP_EQUAL
	require.NoError(t, err)

	dbg := &captureDebugger{Debugger: &nopDebugger{}}

	require.NoError(t, NewEngine().Execute(
		WithScripts(lscript, uscript),
		WithDebugger(dbg),
	))

	require.Positive(t, dbg.steps)
	require.True(t, dbg.sawOpcode)
}
