package interpreter

import "math"

type config interface {
	AfterGenesis() bool
	AfterChronicle() bool
	MaxOps() int
	MaxStackSize() int
	MaxScriptSize() int
	MaxScriptElementSize() int
	MaxScriptNumberLength() int
	MaxPubKeysPerMultiSig() int
}

// Limits applied to transactions before genesis
const (
	MaxOpsBeforeGenesis                = 500
	MaxStackSizeBeforeGenesis          = 1000
	MaxScriptSizeBeforeGenesis         = 10000
	MaxScriptElementSizeBeforeGenesis  = 520
	MaxScriptNumberLengthBeforeGenesis = 4
	MaxPubKeysPerMultiSigBeforeGenesis = 20

	// MaxScriptNumberLengthAfterChronicle is the max script number length
	// after the Chronicle upgrade: 32,000,000 bytes, matching node's
	// consensus/consensus.h:66 MAX_SCRIPT_NUM_LENGTH_AFTER_CHRONICLE =
	// 32*ONE_MEGABYTE (a decimal megabyte, not 32*1024*1024). The name is
	// kept for API stability even though the value is not a power-of-two
	// byte count; see GHSA-rh54-8fpg-8wwf.
	MaxScriptNumberLengthAfterChronicle = 32_000_000
)

// DefaultMaxStackMemory is the stack memory limit, in bytes, that an Engine
// applies to an output created after Genesis unless WithMaxStackMemory sets
// another: bitcoin-sv's default relay policy,
// DEFAULT_STACK_MEMORY_USAGE_POLICY_AFTER_GENESIS (policy/policy.h:153).
// Every element on the data and alt stacks counts its size plus 32 bytes.
// Blocks are validated with no such limit; see WithMaxStackMemory.
const DefaultMaxStackMemory int64 = 100_000_000

type (
	beforeGenesisConfig  struct{}
	afterGenesisConfig   struct{}
	afterChronicleConfig struct{}
)

func (a *afterGenesisConfig) AfterGenesis() bool {
	return true
}

func (b *beforeGenesisConfig) AfterGenesis() bool {
	return false
}

func (c *afterChronicleConfig) AfterGenesis() bool {
	return true
}

func (a *afterGenesisConfig) AfterChronicle() bool {
	return false
}

func (b *beforeGenesisConfig) AfterChronicle() bool {
	return false
}

func (c *afterChronicleConfig) AfterChronicle() bool {
	return true
}

func (a *afterGenesisConfig) MaxStackSize() int {
	return math.MaxInt32
}

func (b *beforeGenesisConfig) MaxStackSize() int {
	return MaxStackSizeBeforeGenesis
}

func (a *afterGenesisConfig) MaxScriptSize() int {
	return math.MaxInt32
}

func (b *beforeGenesisConfig) MaxScriptSize() int {
	return MaxScriptSizeBeforeGenesis
}

func (a *afterGenesisConfig) MaxScriptElementSize() int {
	return math.MaxInt32
}

func (b *beforeGenesisConfig) MaxScriptElementSize() int {
	return MaxScriptElementSizeBeforeGenesis
}

func (a *afterGenesisConfig) MaxScriptNumberLength() int {
	return 750 * 1000 // 750 * 1Kb
}

func (b *beforeGenesisConfig) MaxScriptNumberLength() int {
	return MaxScriptNumberLengthBeforeGenesis
}

func (a *afterGenesisConfig) MaxOps() int {
	return math.MaxInt32
}

func (b *beforeGenesisConfig) MaxOps() int {
	return MaxOpsBeforeGenesis
}

func (a *afterGenesisConfig) MaxPubKeysPerMultiSig() int {
	return math.MaxInt32
}

func (b *beforeGenesisConfig) MaxPubKeysPerMultiSig() int {
	return MaxPubKeysPerMultiSigBeforeGenesis
}

func (c *afterChronicleConfig) MaxStackSize() int {
	return math.MaxInt32
}

func (c *afterChronicleConfig) MaxScriptSize() int {
	return math.MaxInt32
}

func (c *afterChronicleConfig) MaxScriptElementSize() int {
	return math.MaxInt32
}

func (c *afterChronicleConfig) MaxScriptNumberLength() int {
	return MaxScriptNumberLengthAfterChronicle
}

func (c *afterChronicleConfig) MaxOps() int {
	return math.MaxInt32
}

func (c *afterChronicleConfig) MaxPubKeysPerMultiSig() int {
	return math.MaxInt32
}
