package interpreter

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
)

// TestExecutionEpochSelection pins down which UTXO epoch each combination of
// execution options selects. The default, with no epoch named, is
// after-Chronicle.
func TestExecutionEpochSelection(t *testing.T) {
	t.Parallel()

	// OP_2MUL is disabled until Chronicle.
	chronicleOnly, err := script.NewFromASM("OP_1 OP_2MUL OP_2 OP_EQUAL")
	require.NoError(t, err)
	// A 5-byte script number exceeds the pre-Genesis 4-byte limit.
	genesisOnly, err := script.NewFromASM("0000000001 OP_1ADD 0100000001 OP_EQUAL")
	require.NoError(t, err)

	const (
		beforeGenesis = iota
		afterGenesis
		afterChronicle
	)

	tests := []struct {
		name  string
		opts  []ExecutionOptionFunc
		epoch int
	}{
		{name: "no options", epoch: afterChronicle},
		{name: "ForkID and P2SH only", opts: []ExecutionOptionFunc{WithForkID(), WithP2SH()}, epoch: afterChronicle},
		{name: "WithAfterChronicle", opts: []ExecutionOptionFunc{WithAfterChronicle()}, epoch: afterChronicle},
		{name: "WithAfterGenesis", opts: []ExecutionOptionFunc{WithAfterGenesis()}, epoch: afterGenesis},
		{name: "WithBeforeGenesis", opts: []ExecutionOptionFunc{WithBeforeGenesis()}, epoch: beforeGenesis},
		// The spend-era options name the epoch too: on their own the spent
		// output is pre-Genesis.
		{name: "WithGenesis alone", opts: []ExecutionOptionFunc{WithGenesis()}, epoch: beforeGenesis},
		{name: "WithChronicle alone", opts: []ExecutionOptionFunc{WithChronicle()}, epoch: beforeGenesis},
		{name: "WithChronicle plus WithAfterChronicle", opts: []ExecutionOptionFunc{WithChronicle(), WithAfterChronicle()}, epoch: afterChronicle},
		{name: "WithFlags without epoch flag", opts: []ExecutionOptionFunc{WithFlags(scriptflag.VerifyMinimalData)}, epoch: beforeGenesis},
		{name: "WithFlags UTXOAfterGenesis", opts: []ExecutionOptionFunc{WithFlags(scriptflag.UTXOAfterGenesis)}, epoch: afterGenesis},
		{
			name:  "WithFlags UTXOAfterChronicle",
			opts:  []ExecutionOptionFunc{WithFlags(scriptflag.UTXOAfterGenesis | scriptflag.UTXOAfterChronicle)},
			epoch: afterChronicle,
		},
		{name: "WithFlags plus WithAfterChronicle", opts: []ExecutionOptionFunc{WithFlags(scriptflag.VerifyMinimalData), WithAfterChronicle()}, epoch: afterChronicle},
		{name: "WithAfterGenesis plus WithAfterChronicle", opts: []ExecutionOptionFunc{WithAfterGenesis(), WithAfterChronicle()}, epoch: afterChronicle},
		{name: "WithBeforeGenesis plus WithAfterGenesis", opts: []ExecutionOptionFunc{WithBeforeGenesis(), WithAfterGenesis()}, epoch: afterGenesis},
	}

	run := func(lscript *script.Script, opts []ExecutionOptionFunc) error {
		all := append([]ExecutionOptionFunc{WithScripts(lscript, &script.Script{})}, opts...)
		return NewEngine().Execute(all...)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			chronicleErr := run(chronicleOnly, tt.opts)
			genesisErr := run(genesisOnly, tt.opts)

			switch tt.epoch {
			case afterChronicle:
				require.NoError(t, chronicleErr)
				require.NoError(t, genesisErr)
			case afterGenesis:
				require.Error(t, chronicleErr)
				require.NoError(t, genesisErr)
			case beforeGenesis:
				require.Error(t, chronicleErr)
				require.Error(t, genesisErr)
			}
		})
	}
}
