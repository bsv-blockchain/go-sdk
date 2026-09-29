//go:build cgo && !ios && !android && (darwin || linux) && (amd64 || arm64)

package spv

import (
	"testing"

	bdkscript "github.com/bitcoin-sv/bdk/module/gobdk/script"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/bdk"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker/headers_client"
)

// nextBlockHeight is a mainnet height past every activation, standing for the
// block an unmined transaction is validated for.
const nextBlockHeight = 967_897

// compareWithCalculateFlags checks, for every pair of heights a coin mined
// at one is spent at the other, that each tracker's activation heights give
// the flags GoBDK's TxValidator(network).CalculateFlags(coin, spend, true)
// returns, and that an unmined coin spent by an unmined transaction gets the
// flags the node gives a MEMPOOL_HEIGHT coin spent in the block after
// nextSpend. It returns the number of height pairs checked.
func compareWithCalculateFlags(t *testing.T, network string, heights []uint32, nextSpend int32, trackers map[string]chaintracker.ChainTracker) int {
	t.Helper()
	validator, err := bdk.NewValidator(network)
	require.NoError(t, err)
	native := validator.Native()
	checked := 0
	for _, spend := range heights {
		for _, coin := range heights {
			if coin > spend {
				continue
			}
			word := native.CalculateFlags(int32(coin), int32(spend), true) //nolint:gosec // G115 -- heights are below 2^31
			for name, tracker := range trackers {
				require.Equal(t, nodeWordFlags(t, word), activationHeights(tracker).BlockValidationFlags(coin, spend), "%s: coin %d spend %d: node word 0x%x", name, coin, spend, word)
			}
			checked++
		}
	}
	require.Positive(t, checked)

	// An unmined coin: the node resolves MEMPOOL_HEIGHT to the next block.
	const mempoolHeight = 0x7fffffff
	word := native.CalculateFlags(mempoolHeight, nextSpend, true)
	for name, tracker := range trackers {
		require.Equal(t, nodeWordFlags(t, word), activationHeights(tracker).BlockValidationFlags(unminedHeight, unminedHeight), name)
	}
	return checked
}

// TestInputScriptFlagsAgainstBDK compares BlockValidationFlags with
// bitcoin-sv's own per-input flag derivation (GoBDK CalculateFlags for block
// validation) for heights on both sides of every mainnet activation height,
// with the activation heights Verify takes from mainnet chain trackers and
// from trackers that do not say which network they follow.
func TestInputScriptFlagsAgainstBDK(t *testing.T) {
	var heights []uint32
	for _, h := range []uint32{
		mainnetP2SHHeight, mainnetBIP66Height, mainnetBIP65Height, mainnetCSVHeight,
		mainnetUAHFHeight, mainnetDAAHeight, mainnetGenesisHeight, mainnetChronicleHeight,
	} {
		heights = append(heights, h-2, h-1, h, h+1, h+2)
	}
	for h := uint32(0); h < 1_100_000; h += 49_999 {
		heights = append(heights, h)
	}
	checked := compareWithCalculateFlags(t, "main", heights, nextBlockHeight, map[string]chaintracker.ChainTracker{
		"GullibleHeadersClient":           &GullibleHeadersClient{},
		"headers_client.Client":           headers_client.NewClient("https://headers.test", ""),
		"WhatsOnChain main":               chaintracker.NewWhatsOnChain(chaintracker.MainNet, ""),
		"WithActivationHeights (mainnet)": WithActivationHeights(skepticalHeaders{}, scriptflag.MainNetActivationHeights),
	})
	t.Logf("%d (coin, spend) height pairs match CalculateFlags", checked)
}

// TestTestNetFlagsAgainstBDK does the same for testnet's activation heights,
// with the ways a chain tracker reports it follows testnet.
func TestTestNetFlagsAgainstBDK(t *testing.T) {
	h := scriptflag.TestNetActivationHeights
	var heights []uint32
	for _, a := range []uint32{h.P2SH, h.BIP66, h.BIP65, h.CSV, h.UAHF, h.DAA, h.Genesis, h.Chronicle} {
		heights = append(heights, a-2, a-1, a, a+1, a+2)
	}
	for height := uint32(0); height < 1_800_000; height += 99_999 {
		heights = append(heights, height)
	}
	checked := compareWithCalculateFlags(t, "test", heights, 1_800_000, map[string]chaintracker.ChainTracker{
		"WhatsOnChain test":               chaintracker.NewWhatsOnChain(chaintracker.TestNet, ""),
		"WithActivationHeights (testnet)": WithActivationHeights(&GullibleHeadersClient{}, h),
		"headers_client.Client (testnet)": headers_client.NewClient("https://headers.test", "", headers_client.WithActivationHeights(h)),
	})
	t.Logf("%d testnet (coin, spend) height pairs match CalculateFlags", checked)
}

// nodeVerdict replays every unmined transaction reachable from tx through
// bitcoin-sv's transaction and script checks (GoBDK ValidateTransaction in
// block context), as mined in the block at nextBlock, and returns the error
// of the first the node rejects. A spent output's height is the one a merkle
// path in the graph gives its transaction; a transaction with no merkle path
// anywhere in the graph is unmined.
func nodeVerdict(t *testing.T, validator *bdk.Validator, nextBlock int32, name string, tx *transaction.Transaction) error {
	t.Helper()
	mined := make(map[chainhash.Hash]int32)
	var unmined []*transaction.Transaction
	seen := make(map[*transaction.Transaction]bool)
	for queue := []*transaction.Transaction{tx}; len(queue) > 0; queue = queue[1:] {
		cur := queue[0]
		if seen[cur] {
			continue
		}
		seen[cur] = true
		if cur.MerklePath != nil {
			mined[*cur.TxID()] = int32(cur.MerklePath.BlockHeight) //nolint:gosec // G115 -- test heights are below 2^31
			continue
		}
		unmined = append(unmined, cur)
		for _, in := range cur.Inputs {
			if in.SourceTransaction != nil {
				queue = append(queue, in.SourceTransaction)
			}
		}
	}
	for _, cur := range unmined {
		if _, ok := mined[*cur.TxID()]; ok {
			continue
		}
		heights := make([]int32, len(cur.Inputs))
		for i, in := range cur.Inputs {
			heights[i] = nextBlock
			if h, ok := mined[*in.SourceTXID]; ok {
				heights[i] = h
			}
		}
		if err := validator.ValidateTransaction(cur, heights, nextBlock, true); err != nil {
			t.Logf("%s: node: %v", name, err)
			return err
		}
	}
	return nil
}

// TestSPVScenariosAgainstBDK checks that bitcoin-sv reaches the verdict
// Verify reaches on each scenario.
func TestSPVScenariosAgainstBDK(t *testing.T) {
	validator, err := bdk.NewValidator("main")
	require.NoError(t, err)
	for _, sc := range spvScenarios(t) {
		require.Equal(t, sc.valid, nodeVerdict(t, validator, nextBlockHeight, sc.name, sc.tx) == nil, sc.name)
	}
}

// TestSPVAmountScenariosAgainstBDK checks that bitcoin-sv's transaction
// checks reject each amount scenario Verify rejects, for the same reason, and
// accept the others.
func TestSPVAmountScenariosAgainstBDK(t *testing.T) {
	validator, err := bdk.NewValidator("main")
	require.NoError(t, err)
	reasons := map[error][]bdkscript.DoSErrorCode{
		ErrOutputsExceedInputs: {bdkscript.DOS_ERR_INPUTS_BELOW_OUTPUTS},
		ErrValueOutOfRange: {
			bdkscript.DOS_ERR_OUTPUT_NEGATIVE, bdkscript.DOS_ERR_OUTPUT_TOO_LARGE,
			bdkscript.DOS_ERR_OUTPUT_TOTAL_TOO_LARGE, bdkscript.DOS_ERR_INPUT_VALUES_OUT_OF_RANGE,
		},
		ErrDuplicateInput:  {bdkscript.DOS_ERR_DUPLICATE_INPUTS},
		ErrNoInputs:        {bdkscript.DOS_ERR_VIN_EMPTY},
		ErrNoOutputs:       {bdkscript.DOS_ERR_VOUT_EMPTY},
		ErrP2SHOutput:      {bdkscript.DOS_ERR_P2SH_OUTPUT_POST_GENESIS},
		ErrNullOutpoint:    {bdkscript.DOS_ERR_NULL_PREVOUT},
		ErrUnminedCoinbase: {bdkscript.DOS_ERR_COINBASE_NOT_ALLOWED},
	}
	for _, sc := range amountScenarios(t) {
		nodeErr := nodeVerdict(t, validator, nextBlockHeight, sc.name, sc.tx)
		if sc.err == nil {
			require.NoError(t, nodeErr, sc.name)
			continue
		}
		var dos bdkscript.DoSError
		require.ErrorAs(t, nodeErr, &dos, sc.name)
		require.Contains(t, reasons[sc.err], dos.Code(), sc.name)
	}
}

// TestSPVTestNetScenariosAgainstBDK checks that bitcoin-sv on testnet reaches
// Verify's verdict, with testnet's activation heights, on spends of a
// P2SH-shaped output mined at a height that is before Genesis on testnet and
// after it on mainnet.
func TestSPVTestNetScenariosAgainstBDK(t *testing.T) {
	validator, err := bdk.NewValidator("test")
	require.NoError(t, err)
	tracker := WithActivationHeights(&GullibleHeadersClient{}, scriptflag.TestNetActivationHeights)
	for _, signed := range []bool{false, true} {
		tx := p2shSpend(t, 700_000, signed)
		verified, _ := Verify(t.Context(), tx, tracker, nil)
		require.Equal(t, signed, verified)
		require.Equal(t, verified, nodeVerdict(t, validator, 1_800_000, "testnet P2SH", tx) == nil)
	}
}
