package spv

import "errors"

var (
	ErrFeeTooLow                = errors.New("fee is too low")
	ErrInvalidMerklePath        = errors.New("invalid merkle path")
	ErrMissingSourceTransaction = errors.New("missing source transaction")
	ErrScriptVerificationFailed = errors.New("script verification failed")

	// ErrSourceTransactionMismatch is returned when an input's
	// SourceTransaction is not the transaction its SourceTXID names.
	ErrSourceTransactionMismatch = errors.New("source transaction does not match the input's source txid")
	// ErrDuplicateInput is returned when an unmined transaction spends an
	// outpoint more than once.
	ErrDuplicateInput = errors.New("duplicate input")
	// ErrValueOutOfRange is returned when an amount an unmined transaction
	// spends or pays, or the total of either, exceeds 21,000,000 BSV.
	ErrValueOutOfRange = errors.New("value out of range")
	// ErrOutputsExceedInputs is returned when an unmined transaction pays
	// more than it spends.
	ErrOutputsExceedInputs = errors.New("outputs exceed inputs")
	// ErrNoInputs is returned when an unmined transaction has no inputs.
	ErrNoInputs = errors.New("transaction has no inputs")
	// ErrNoOutputs is returned when an unmined transaction has no outputs.
	ErrNoOutputs = errors.New("transaction has no outputs")
	// ErrP2SHOutput is returned when an unmined transaction creates a
	// pay-to-script-hash output, which blocks after Genesis reject.
	ErrP2SHOutput = errors.New("transaction creates a P2SH output")
	// ErrUnminedCoinbase is returned when a transaction without a merkle
	// path looks like a coinbase (one input spending the null outpoint):
	// CheckRegularTransaction rejects every coinbase, so it can only be
	// valid as the first transaction of a block, which Verify never sees.
	ErrUnminedCoinbase = errors.New("unmined transaction is a coinbase")
	// ErrNullOutpoint is returned when an unmined, non-coinbase
	// transaction has an input spending the null outpoint (zero txid,
	// index 0xffffffff).
	ErrNullOutpoint = errors.New("input spends the null outpoint")
	// ErrNonFinalTransaction is returned when an unmined transaction is
	// not final: some input's sequence number is not final and either its
	// nLockTime has not yet been reached by the next block's height, or
	// its nLockTime is time-based, whose finality Verify cannot determine
	// without the chain tip's median time past.
	ErrNonFinalTransaction = errors.New("transaction is not final")
	// ErrPrematureCoinbaseSpend is returned when an input spends a
	// coinbase output that is not yet 100 blocks deep, or whose source
	// transaction is a coinbase not proven mined.
	ErrPrematureCoinbaseSpend = errors.New("input spends an immature coinbase output")
	// ErrConfiscationTransaction is returned when an unmined transaction is
	// a confiscation transaction (its output 0 starts with OP_FALSE
	// OP_RETURN 'cftx'). A node accepts one only if it is on the node's
	// confiscation whitelist, which Verify cannot see.
	ErrConfiscationTransaction = errors.New("unmined transaction is a confiscation transaction")
	// ErrPrematureConfiscationSpend is returned when an input spends an
	// output of a confiscation transaction that is not yet 1000 blocks deep.
	ErrPrematureConfiscationSpend = errors.New("input spends an immature confiscation output")
)
