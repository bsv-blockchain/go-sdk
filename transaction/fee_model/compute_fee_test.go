package feemodel

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/stretchr/testify/require"
)

// mockUnlockingScriptTemplate implements transaction.UnlockingScriptTemplate
// so we can test the EstimateLength branch in ComputeFee.
type mockUnlockingScriptTemplate struct {
	estimatedLen uint32
}

func (m *mockUnlockingScriptTemplate) Sign(_ *transaction.Transaction, _ uint32) (*script.Script, error) {
	return nil, nil
}

func (m *mockUnlockingScriptTemplate) EstimateLength(_ *transaction.Transaction, _ uint32) uint32 {
	return m.estimatedLen
}

func makeLockingScript(t *testing.T, hex string) *script.Script {
	t.Helper()
	s, err := script.NewFromHex(hex)
	require.NoError(t, err)
	return s
}

// buildTxWithUnlockingScript creates a minimal valid transaction where every
// input already has an unlocking script set.
func buildTxWithUnlockingScript(t *testing.T) *transaction.Transaction {
	t.Helper()
	tx := transaction.NewTransaction()

	// Create a previous transaction that provides the source output.
	prevTx := transaction.NewTransaction()
	lockScript := makeLockingScript(t, "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac")
	prevTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      5000,
		LockingScript: lockScript,
	})

	input := &transaction.TransactionInput{
		SourceTxOutIndex: 0,
		SourceTransaction: prevTx,
		SequenceNumber:   0xffffffff,
	}
	s := script.NewFromBytes([]byte{0x51}) // OP_1 as a minimal unlocking script
	input.UnlockingScript = s
	tx.AddInput(input)

	outputScript := makeLockingScript(t, "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac")
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      4000,
		LockingScript: outputScript,
	})

	return tx
}

// buildTxWithTemplate creates a transaction where every input has an
// UnlockingScriptTemplate but no pre-set unlocking script.
func buildTxWithTemplate(t *testing.T, estimatedLen uint32) *transaction.Transaction {
	t.Helper()
	tx := transaction.NewTransaction()

	prevTx := transaction.NewTransaction()
	lockScript := makeLockingScript(t, "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac")
	prevTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      5000,
		LockingScript: lockScript,
	})

	input := &transaction.TransactionInput{
		SourceTxOutIndex:        0,
		SourceTransaction:       prevTx,
		SequenceNumber:          0xffffffff,
		UnlockingScriptTemplate: &mockUnlockingScriptTemplate{estimatedLen: estimatedLen},
	}
	tx.AddInput(input)

	outputScript := makeLockingScript(t, "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac")
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      4000,
		LockingScript: outputScript,
	})

	return tx
}

// buildTxWithNoScript creates a transaction where an input has neither an
// unlocking script nor a template – this should trigger ErrNoUnlockingScript.
func buildTxWithNoScript(t *testing.T) *transaction.Transaction {
	t.Helper()
	tx := transaction.NewTransaction()

	prevTx := transaction.NewTransaction()
	lockScript := makeLockingScript(t, "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac")
	prevTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      5000,
		LockingScript: lockScript,
	})

	input := &transaction.TransactionInput{
		SourceTxOutIndex:  0,
		SourceTransaction: prevTx,
		SequenceNumber:    0xffffffff,
		// No UnlockingScript and no UnlockingScriptTemplate
	}
	tx.AddInput(input)

	outputScript := makeLockingScript(t, "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac")
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      4000,
		LockingScript: outputScript,
	})

	return tx
}

func TestComputeFee_WithUnlockingScript(t *testing.T) {
	t.Parallel()

	model := &SatoshisPerKilobyte{Satoshis: 100}
	tx := buildTxWithUnlockingScript(t)

	fee, err := model.ComputeFee(tx)
	require.NoError(t, err)
	require.Greater(t, fee, uint64(0), "fee should be positive")
}

func TestComputeFee_WithTemplate(t *testing.T) {
	t.Parallel()

	model := &SatoshisPerKilobyte{Satoshis: 100}
	tx := buildTxWithTemplate(t, 106)

	fee, err := model.ComputeFee(tx)
	require.NoError(t, err)
	require.Greater(t, fee, uint64(0), "fee should be positive")
}

func TestComputeFee_NoScriptReturnsError(t *testing.T) {
	t.Parallel()

	model := &SatoshisPerKilobyte{Satoshis: 100}
	tx := buildTxWithNoScript(t)

	_, err := model.ComputeFee(tx)
	require.ErrorIs(t, err, ErrNoUnlockingScript)
}

func TestComputeFee_ZeroSatoshisPerKB(t *testing.T) {
	t.Parallel()

	model := &SatoshisPerKilobyte{Satoshis: 0}
	tx := buildTxWithUnlockingScript(t)

	fee, err := model.ComputeFee(tx)
	require.NoError(t, err)
	require.Equal(t, uint64(0), fee, "zero rate should produce zero fee")
}

func TestComputeFee_EmptyUnlockingScriptFallsBackToTemplate(t *testing.T) {
	t.Parallel()

	// An input with a non-nil but empty unlocking script should fall through
	// to the template branch.
	tx := transaction.NewTransaction()

	prevTx := transaction.NewTransaction()
	lockScript := makeLockingScript(t, "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac")
	prevTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      5000,
		LockingScript: lockScript,
	})

	emptyScript := script.NewFromBytes([]byte{})
	input := &transaction.TransactionInput{
		SourceTxOutIndex:        0,
		SourceTransaction:       prevTx,
		SequenceNumber:          0xffffffff,
		UnlockingScript:         emptyScript, // non-nil but empty
		UnlockingScriptTemplate: &mockUnlockingScriptTemplate{estimatedLen: 50},
	}
	tx.AddInput(input)

	outputScript := makeLockingScript(t, "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac")
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      4000,
		LockingScript: outputScript,
	})

	model := &SatoshisPerKilobyte{Satoshis: 100}
	fee, err := model.ComputeFee(tx)
	require.NoError(t, err)
	require.Greater(t, fee, uint64(0))
}

func TestComputeFee_MultipleInputs(t *testing.T) {
	t.Parallel()

	// Build a transaction with two inputs – one with a script, one with a template.
	tx := transaction.NewTransaction()

	prevTx := transaction.NewTransaction()
	lockScript := makeLockingScript(t, "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac")
	prevTx.AddOutput(&transaction.TransactionOutput{Satoshis: 5000, LockingScript: lockScript})
	prevTx.AddOutput(&transaction.TransactionOutput{Satoshis: 5000, LockingScript: lockScript})

	// First input: has an unlocking script.
	s := script.NewFromBytes([]byte{0x51})
	input1 := &transaction.TransactionInput{
		SourceTxOutIndex:  0,
		SourceTransaction: prevTx,
		SequenceNumber:    0xffffffff,
		UnlockingScript:   s,
	}
	tx.AddInput(input1)

	// Second input: uses a template.
	input2 := &transaction.TransactionInput{
		SourceTxOutIndex:        1,
		SourceTransaction:       prevTx,
		SequenceNumber:          0xffffffff,
		UnlockingScriptTemplate: &mockUnlockingScriptTemplate{estimatedLen: 106},
	}
	tx.AddInput(input2)

	outputScript := makeLockingScript(t, "76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac")
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 9000, LockingScript: outputScript})

	model := &SatoshisPerKilobyte{Satoshis: 500}
	fee, err := model.ComputeFee(tx)
	require.NoError(t, err)
	require.Greater(t, fee, uint64(0))
}

func TestComputeFee_FeeScalesWithSize(t *testing.T) {
	t.Parallel()

	// A template with a larger estimated script should produce a higher fee.
	model := &SatoshisPerKilobyte{Satoshis: 1000}

	smallTx := buildTxWithTemplate(t, 10)
	largeTx := buildTxWithTemplate(t, 1000)

	smallFee, err := model.ComputeFee(smallTx)
	require.NoError(t, err)

	largeFee, err := model.ComputeFee(largeTx)
	require.NoError(t, err)

	require.Greater(t, largeFee, smallFee, "larger tx should cost more")
}

func TestErrNoUnlockingScript(t *testing.T) {
	require.EqualError(t, ErrNoUnlockingScript, "inputs must have an unlocking script or an unlocker")
}
