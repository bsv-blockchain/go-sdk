package spv

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// maxMoney is bitcoin-sv's MAX_MONEY (amount.h) in satoshis.
const maxMoney = 21_000_000 * 100_000_000

// amountScenario is a transaction chain whose unmined transactions bitcoin-sv
// accepts, when err is nil, or rejects for their amounts, when Verify must
// return err.
type amountScenario struct {
	name string
	tx   *transaction.Transaction
	err  error
}

// amountScenarios builds the chains TestSPVVerifyAmounts verifies and
// TestSPVAmountScenariosAgainstBDK replays through the node.
func amountScenarios(t *testing.T) []amountScenario {
	t.Helper()
	coin := minedCoins(t, 1000)
	one := minedCoins(t, 1)
	// An unmined parent spends 1 satoshi and creates 21,000,000 BSV, which a
	// balanced child then spends.
	inflating := spendCoins([]coinRef{{one, 0}}, maxMoney)
	huge := minedCoins(t, maxMoney, maxMoney)
	full := minedCoins(t, maxMoney-1000, 1000)
	wrapping := minedCoins(t, 1<<63, 1<<63)
	createsP2SH := spendCoins([]coinRef{{coin, 0}}, 1000)
	createsP2SH.Outputs[0].LockingScript = p2shOf([]byte{0x51})

	// A second, EF-style input spending the null outpoint alongside a
	// genuine one: not coinbase-shaped (more than one input), so it is
	// rejected for the null outpoint specifically.
	nullOutpoint := spendCoins([]coinRef{{coin, 0}}, 500)
	null := &transaction.TransactionInput{
		SourceTXID:       &chainhash.Hash{},
		SourceTxOutIndex: transaction.DefaultSequenceNumber,
		UnlockingScript:  &script.Script{},
		SequenceNumber:   transaction.DefaultSequenceNumber,
	}
	null.SetSourceTxOutput(&transaction.TransactionOutput{Satoshis: 500, LockingScript: opTrue})
	nullOutpoint.Inputs = append(nullOutpoint.Inputs, null)

	// A transaction that is itself coinbase-shaped (one input spending the
	// null outpoint) and unmined: CheckRegularTransaction rejects every
	// coinbase, so this can never be a valid unmined transaction.
	cbIn := &transaction.TransactionInput{
		SourceTXID:       &chainhash.Hash{},
		SourceTxOutIndex: transaction.DefaultSequenceNumber,
		UnlockingScript:  &script.Script{},
		SequenceNumber:   transaction.DefaultSequenceNumber,
	}
	cbIn.SetSourceTxOutput(&transaction.TransactionOutput{Satoshis: 0, LockingScript: &script.Script{}})
	unminedCoinbase := transaction.NewTransaction()
	unminedCoinbase.AddInput(cbIn)
	unminedCoinbase.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: opTrue})

	return []amountScenario{
		{"outputs equal inputs", spendCoins([]coinRef{{coin, 0}}, 600, 400), nil},
		{"inputs exceed outputs by the fee", spendCoins([]coinRef{{coin, 0}}, 900), nil},
		{"outputs exceed inputs", spendCoins([]coinRef{{coin, 0}}, 1001), ErrOutputsExceedInputs},
		{"unmined parent creates 21M BSV from 1 satoshi", spendCoins([]coinRef{{inflating, 0}}, maxMoney), ErrOutputsExceedInputs},
		{"input total of MAX_MONEY", spendCoins([]coinRef{{full, 0}, {full, 1}}, maxMoney), nil},
		{"output above MAX_MONEY", spendCoins([]coinRef{{coin, 0}}, maxMoney+1), ErrValueOutOfRange},
		{"output total above MAX_MONEY", spendCoins([]coinRef{{coin, 0}}, maxMoney, 1), ErrValueOutOfRange},
		// Without a range check the two outputs would total 0 modulo 2^64.
		{"outputs wrapping uint64", spendCoins([]coinRef{{coin, 0}}, 1<<63, 1<<63), ErrValueOutOfRange},
		{"input above MAX_MONEY", spendCoins([]coinRef{{minedCoins(t, maxMoney+1), 0}}, 1), ErrValueOutOfRange},
		{"input total above MAX_MONEY", spendCoins([]coinRef{{huge, 0}, {huge, 1}}, 1), ErrValueOutOfRange},
		{"inputs wrapping uint64", spendCoins([]coinRef{{wrapping, 0}, {wrapping, 1}}, 1), ErrValueOutOfRange},
		// Spending an outpoint twice would count its amount twice.
		{"outpoint spent twice", spendCoins([]coinRef{{coin, 0}, {coin, 0}}, 2000), ErrDuplicateInput},
		{"outpoint spent twice without inflating", spendCoins([]coinRef{{coin, 0}, {coin, 0}}, 1000), ErrDuplicateInput},
		{"no outputs", spendCoins([]coinRef{{coin, 0}}), ErrNoOutputs},
		{"no inputs", spendCoins(nil, 0), ErrNoInputs},
		{"creates a P2SH output", createsP2SH, ErrP2SHOutput},
		{"spends the null outpoint", nullOutpoint, ErrNullOutpoint},
		{"looks like an unmined coinbase", unminedCoinbase, ErrUnminedCoinbase},
	}
}

// TestSPVVerifyAmounts checks that Verify rejects an unmined transaction
// whose amounts bitcoin-sv rejects (CheckTransactionCommon and
// Consensus::CheckTxInputs, validation.cpp:540-558 and 2639-2652, and the
// duplicate-input check at validation.cpp:625-637).
func TestSPVVerifyAmounts(t *testing.T) {
	for _, sc := range amountScenarios(t) {
		verified, err := Verify(t.Context(), sc.tx, &GullibleHeadersClient{}, nil)
		if sc.err == nil {
			require.NoError(t, err, sc.name)
			require.True(t, verified, sc.name)
			continue
		}
		require.ErrorIs(t, err, sc.err, sc.name)
		require.False(t, verified, sc.name)
	}
}

// TestSPVVerifyMinedAmountsNotChecked checks that the amounts of a
// transaction proven mined are not checked, as the block that holds it
// already was: only unmined transactions must spend at least what they pay.
func TestSPVVerifyMinedAmountsNotChecked(t *testing.T) {
	coinbase := minedCoins(t, 50*100_000_000)
	require.Empty(t, coinbase.Inputs)
	verified, err := Verify(t.Context(), coinbase, &GullibleHeadersClient{}, nil)
	require.NoError(t, err)
	require.True(t, verified)
}
