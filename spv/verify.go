package spv

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
)

// maxSatoshis is bitcoin-sv's MAX_MONEY (amount.h:130): no amount a
// transaction spends or pays, nor the total of either, may exceed it.
const maxSatoshis uint64 = 21_000_000 * 100_000_000

// coinbaseMaturity is bitcoin-sv's COINBASE_MATURITY (consensus/consensus.h):
// a coinbase output cannot be spent until it is this many blocks deep.
const coinbaseMaturity = 100

// confiscationMaturity is bitcoin-sv's CONFISCATION_MATURITY
// (consensus/consensus.h): a confiscation transaction's output cannot be
// spent until it is this many blocks deep.
const confiscationMaturity = 1000

// lockTimeThreshold is bitcoin-sv's LOCKTIME_THRESHOLD (script/script.h): an
// nLockTime below it is a block height, at or above it a Unix time.
const lockTimeThreshold = 500_000_000

// Verify checks t and its unmined ancestors. A transaction with a merkle path
// is accepted once chainTracker confirms the path. Every other transaction is
// checked as bitcoin-sv checks it when mining it in the next block:
//
//   - it must have inputs and outputs, must not itself look like a
//     coinbase, must create no pay-to-script-hash output, and no input may
//     spend the null outpoint (CheckRegularTransaction);
//   - it must be final: every input's sequence number is final, or its
//     nLockTime has passed (IsFinalTx), judged against chainTracker's
//     current height or, for a time-based nLockTime, the median time past
//     of a chainTracker that implements MedianTimePastProvider. Without
//     one, a non-final input under a time-based nLockTime is rejected;
//   - it must not be a confiscation transaction (output 0 starting with
//     OP_FALSE OP_RETURN 'cftx'), which a node accepts only from its
//     confiscation whitelist, which Verify cannot see;
//   - the output each of its inputs spends must exist, and, when that
//     output is a coinbase's, must be at least 100 blocks deep, or, when it
//     is a confiscation transaction's, at least 1000 blocks deep
//     (Consensus::CheckTxInputs);
//   - it must spend each outpoint once, and keep every amount and the
//     totals it spends and pays within 21,000,000 BSV, paying no more than
//     it spends;
//   - its scripts must pass verification with the flags the node applies
//     (scriptflag.ActivationHeights.BlockValidationFlags).
//
// The finality, coinbase-maturity and confiscation-maturity checks are
// skipped for a GullibleHeadersClient, whose CurrentHeight is a placeholder.
//
// An input's SourceTransaction must be the transaction its SourceTXID names.
// feeModel, when non-nil, is checked against t only.
//
// Scripts run with the engine's default stack memory limit, bitcoin-sv's
// relay policy of 100,000,000 bytes (interpreter.DefaultMaxStackMemory),
// which a default node applies before relaying a transaction; block
// validation has no such limit.
//
// Verify stops once ctx is done, also in the middle of a script
// (interpreter.WithContext), and returns false with an error for which both
// errors.Is(err, ctx.Err()) and errors.Is(err, ErrScriptVerificationFailed)
// hold. bitcoin-sv bounds the time it spends validating a transaction for
// relay (-maxstdtxvalidationduration, 3 ms by default, and
// -maxnonstdtxvalidationduration, 1 s; txn_validation_config.h) and puts no
// limit on block validation. Verify has no limit of its own, so a caller
// verifying transactions from untrusted parties should give ctx a deadline.
//
// An output supplied with SetSourceTxOutput for an input without a
// SourceTransaction, as in an Extended Format transaction, is trusted as
// given: nothing proves that it exists, its amount, its era (but see P2SH
// below) or that it is not an immature coinbase or confiscation output. Only
// a transaction
// whose inputs all carry their source transactions, as a BEEF does, is
// verified back to merkle-proven ancestors.
//
// Every merkle path Verify reaches is verified before any block height is
// used. The era of a spent output follows the verified block height of its
// source transaction on the network chainTracker follows: a tracker that
// implements ActivationHeightsProvider, such as chaintracker.WhatsOnChain,
// supplies that network's heights, and any other tracker is taken to follow
// mainnet (see WithActivationHeights). An output whose source transaction is
// not proven mined, including one supplied without its source transaction,
// is treated as created after Chronicle, with one exception: a
// pay-to-script-hash-shaped output (script.Script.IsP2SH) is always treated
// as created before Genesis, unless its source transaction is present, is
// proven mined, and looks like a coinbase, because CheckRegularTransaction
// rejects every non-coinbase transaction that creates a P2SH output after
// Genesis, so a P2SH-shaped output can only exist pre-Genesis or as a
// coinbase's.
//
// Verify cannot tell a mined transaction whose merkle path was left out from
// one that was never mined: it checks such a transaction as unmined, under
// current rules. A pre-Genesis or pre-Chronicle transaction presented this
// way is checked as though it were created after Chronicle, so an output
// that only pre-Genesis or pre-Chronicle rules make unspendable, such as a
// bare OP_RETURN output or one using a number wider than 4 bytes or an
// element wider than 520 bytes, would count as spendable. P2SH-shaped
// outputs are the exception above. This is the same trust as spending an
// output that is already spent: Verify does not see the UTXO set, only the
// network's acceptance of a transaction settles it. Nor does Verify see the
// node's frozen-TXO blacklists: a transaction spending a frozen output
// passes Verify, though a node that enforces the freeze rejects it.
func Verify(ctx context.Context, t *transaction.Transaction,
	chainTracker chaintracker.ChainTracker,
	feeModel transaction.FeeModel,
) (bool, error) {
	return verify(ctx, t, chainTracker, feeModel)
}

// VerifyScripts checks t and its unmined ancestors as Verify does, with a
// GullibleHeadersClient: no merkle path is checked against a chain. It
// therefore trusts the block height each merkle path states, and with it the
// era of every output spent, except that a P2SH-shaped output is still taken
// as created before Genesis. It skips transaction finality and coinbase and
// confiscation maturity, which need the chain tip.
func VerifyScripts(ctx context.Context, t *transaction.Transaction) (bool, error) {
	return verify(ctx, t, &GullibleHeadersClient{}, nil)
}

// verify is Verify's and VerifyScripts' shared implementation.
func verify(ctx context.Context, t *transaction.Transaction,
	chainTracker chaintracker.ChainTracker,
	feeModel transaction.FeeModel,
) (bool, error) {
	if chainTracker == nil {
		chainTracker = chaintracker.NewWhatsOnChain(chaintracker.MainNet, "")
	}
	// Read before chainTracker is wrapped in a memoTracker, which implements
	// neither ActivationHeightsProvider nor MedianTimePastProvider.
	heights := activationHeights(chainTracker)
	mtpProvider, _ := trackerAs[MedianTimePastProvider](chainTracker)

	// Validate fees only on the root transaction, not ancestors
	if feeModel != nil {
		txFee, err := t.GetFee()
		if err != nil {
			return false, err
		}
		requiredFee, err := feeModel.ComputeFee(t)
		if err != nil {
			return false, err
		}
		if txFee < requiredFee {
			return false, fmt.Errorf("%w: paid %d, required %d", ErrFeeTooLow, txFee, requiredFee)
		}
	}

	g := &txGraph{
		ctx:          ctx,
		chainTracker: newMemoTracker(chainTracker),
		skipChainTip: hasNoRealChainTip(chainTracker),
		mtpProvider:  mtpProvider,
		txids:        make(map[*transaction.Transaction]chainhash.Hash),
		heights:      make(map[chainhash.Hash]uint32),
	}
	if err := g.proveMined(t); err != nil {
		return false, err
	}
	if err := g.verifyUnmined(t, heights); err != nil {
		return false, err
	}
	return true, nil
}

// txGraph is what Verify learns about the transactions it reaches.
type txGraph struct {
	ctx          context.Context //nolint:containedctx // g is created fresh per Verify call and threaded through many unexported helpers (proveHeight, tip) that have no ctx parameter of their own
	chainTracker chaintracker.ChainTracker
	// skipChainTip omits the checks that need the chain tip (finality and
	// coinbase and confiscation maturity), for a tracker without a real one.
	skipChainTip bool
	// mtpProvider is the caller's chainTracker as a MedianTimePastProvider,
	// or nil.
	mtpProvider MedianTimePastProvider
	// mtp caches medianTimePast's result for this Verify call.
	mtp *uint32

	// txids holds the txid of each Transaction value, computed once from its
	// serialization rather than taken from a cache set with SetTxHash.
	txids map[*transaction.Transaction]chainhash.Hash
	// heights holds the block height of each txid a verified merkle path
	// proves mined.
	heights map[chainhash.Hash]uint32
	// outputFingerprints caches outputFingerprint's result per
	// *TransactionOutput pointer, for evidenceOf.
	outputFingerprints map[*transaction.TransactionOutput]chainhash.Hash
}

// txid returns the txid of tx.
func (g *txGraph) txid(tx *transaction.Transaction) (chainhash.Hash, error) {
	if txid, ok := g.txids[tx]; ok {
		return txid, nil
	}
	for vin, input := range tx.Inputs {
		if input == nil || input.SourceTXID == nil {
			return chainhash.Hash{}, fmt.Errorf("%w: input %d names no source transaction", ErrMissingSourceTransaction, vin)
		}
	}
	txid := chainhash.DoubleHashH(tx.Bytes())
	g.txids[tx] = txid
	return txid, nil
}

// tip returns the chain tracker's current height: the height of the last
// mined block, so tx would be mined in the block at tip+1
// (ContextualCheckTransactionForCurrentBlock, validation.cpp:5955-5975). It
// is fetched from chainTracker at most once per Verify call (chainTracker
// memoizes it), and only by a check that needs it.
func (g *txGraph) tip() (uint32, error) {
	return g.chainTracker.CurrentHeight(g.ctx)
}

// hasNoRealChainTip reports whether chainTracker's CurrentHeight is a
// placeholder rather than the chain tip, as GullibleHeadersClient's is.
func hasNoRealChainTip(chainTracker chaintracker.ChainTracker) bool {
	_, ok := trackerAs[interface{ noRealChainTip() }](chainTracker)
	return ok
}

// proveMined walks t and every transaction it reaches through transactions
// without a merkle path, once per Transaction value. It checks that each
// input's source transaction is the one its SourceTXID names, as ts-sdk's
// Transaction.verify does, and verifies every merkle path it finds against
// chainTracker, so that no block height is used unverified and no copy of a
// transaction can claim another height unchecked. The ancestors of a
// transaction with a merkle path are not walked.
func (g *txGraph) proveMined(t *transaction.Transaction) error {
	seen := map[*transaction.Transaction]struct{}{t: {}}
	for queue := []*transaction.Transaction{t}; len(queue) > 0; queue = queue[1:] {
		tx := queue[0]
		txid, err := g.txid(tx)
		if err != nil {
			return err
		}
		if tx.MerklePath != nil {
			if err := g.proveHeight(tx.MerklePath, txid); err != nil {
				return err
			}
			continue
		}
		for vin, input := range tx.Inputs {
			src := input.SourceTransaction
			if src == nil {
				continue
			}
			srcTxid, err := g.txid(src)
			if err != nil {
				return err
			}
			if !srcTxid.IsEqual(input.SourceTXID) {
				return fmt.Errorf("%w: input %d of %s names %s but carries %s", ErrSourceTransactionMismatch, vin, txid, input.SourceTXID, srcTxid)
			}
			if _, ok := seen[src]; !ok {
				seen[src] = struct{}{}
				queue = append(queue, src)
			}
		}
	}
	return nil
}

// proveHeight verifies that mp proves txid mined and records the block
// height it proves. Verified merkle paths that put one transaction at two
// heights cannot both hold.
func (g *txGraph) proveHeight(mp *transaction.MerklePath, txid chainhash.Hash) error {
	valid, err := mp.Verify(g.ctx, &txid, g.chainTracker)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("%w for transaction %s", ErrInvalidMerklePath, txid)
	}
	if height, ok := g.heights[txid]; ok && height != mp.BlockHeight {
		return fmt.Errorf("%w: transaction %s is proven at heights %d and %d", ErrInvalidMerklePath, txid, height, mp.BlockHeight)
	}
	g.heights[txid] = mp.BlockHeight
	return nil
}

// evidence is what a Transaction value's inputs say about the outputs they
// spend, for verifiedTx: whether an input carries its source transaction,
// carries a directly supplied output (SetSourceTxOutput), or neither.
type evidence struct {
	txid chainhash.Hash
	// spent is a per-input fingerprint. SourceTXID and SourceTxOutIndex are
	// not included: they are part of tx's own serialization, so they are
	// already fixed by txid.
	spent chainhash.Hash
}

// evidenceOf returns the evidence tx's inputs present, for verifiedTx.
//
// Two Transaction values can carry the same txid but different evidence: a
// SourceTransaction pointer and an output supplied with SetSourceTxOutput
// are both auxiliary to the transaction, outside what its txid hashes, so an
// attacker can pair a genuine txid with fabricated evidence. When an input
// carries its source transaction, only that fact is hashed, not which
// Transaction value it points to: proveMined already checked that the value
// hashes to the input's SourceTXID, which is fixed by tx's own txid, so any
// value that carries a matching source transaction spends the same output.
//
// A directly supplied output (SetSourceTxOutput) is fingerprinted through
// g.outputFingerprint, which caches the result per *TransactionOutput
// pointer for the life of one Verify call: several Transaction values built
// to share one such pointer -- as a caller graph of pointer-distinct copies
// spending one large supplied output can -- then hash that output's locking
// script once, not once per value walked.
func (g *txGraph) evidenceOf(tx *transaction.Transaction) chainhash.Hash {
	var buf []byte
	for _, input := range tx.Inputs {
		switch {
		case input.SourceTransaction != nil:
			buf = append(buf, 's')
		case input.SourceTxOutput() != nil:
			buf = append(buf, 'o')
			fp := g.outputFingerprint(input.SourceTxOutput())
			buf = append(buf, fp[:]...)
		default:
			buf = append(buf, 'm')
		}
	}
	return chainhash.DoubleHashH(buf)
}

// outputFingerprint returns a digest of out's amount and locking script,
// computed once per distinct *TransactionOutput pointer and cached in
// g.outputFingerprints for the rest of the Verify call.
func (g *txGraph) outputFingerprint(out *transaction.TransactionOutput) chainhash.Hash {
	if fp, ok := g.outputFingerprints[out]; ok {
		return fp
	}
	var buf []byte
	buf = binary8(buf, out.Satoshis)
	var script []byte
	if out.LockingScript != nil {
		script = out.LockingScript.Bytes()
	}
	buf = binary8(buf, uint64(len(script)))
	buf = append(buf, script...)
	fp := chainhash.DoubleHashH(buf)
	if g.outputFingerprints == nil {
		g.outputFingerprints = make(map[*transaction.TransactionOutput]chainhash.Hash)
	}
	g.outputFingerprints[out] = fp
	return fp
}

// binary8 appends v to buf as 8 little-endian bytes.
func binary8(buf []byte, v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return append(buf, b[:]...)
}

// verifyUnmined verifies t, unless it is proven mined, and every unmined
// transaction it spends from. Every Transaction value reachable from t
// through SourceTransaction is walked once, stopping at a value whose txid a
// verified merkle path proves mined, as proveMined already found. verifyTx
// itself runs once per distinct (txid, evidence) pair rather than once per
// value: values that share a txid and carry the same evidence for every
// input must reach the same verdict (see evidenceOf), so a chain of k
// diamonds, which reaches the same Transaction value twice at each level,
// still costs O(k) verifications rather than 2^k.
func (g *txGraph) verifyUnmined(t *transaction.Transaction, heights scriptflag.ActivationHeights) error {
	walked := map[*transaction.Transaction]struct{}{t: {}}
	verified := map[evidence]struct{}{}
	queue := []*transaction.Transaction{t}
	for len(queue) > 0 {
		tx := queue[0]
		queue = queue[1:]

		txid, err := g.txid(tx)
		if err != nil {
			return err
		}
		if _, mined := g.heights[txid]; mined {
			continue
		}

		ev := evidence{txid: txid, spent: g.evidenceOf(tx)}
		if _, ok := verified[ev]; !ok {
			if err := g.verifyTx(tx, heights); err != nil {
				return err
			}
			verified[ev] = struct{}{}
		}

		for _, input := range tx.Inputs {
			src := input.SourceTransaction
			if src == nil {
				continue
			}
			if _, ok := walked[src]; ok {
				continue
			}
			walked[src] = struct{}{}
			queue = append(queue, src)
		}
	}
	return nil
}

// outpoint is an output a transaction input spends.
type outpoint struct {
	txid chainhash.Hash
	vout uint32
}

// verifyTx checks the unmined transaction tx as bitcoin-sv does when mining
// it: that it is not a coinbase and spends no null outpoint
// (CheckRegularTransaction, validation.cpp:604-637), its output amounts
// (CheckTransactionCommon, validation.cpp:540-558), that it creates no
// pay-to-script-hash output and spends each outpoint once
// (CheckRegularTransaction, validation.cpp:610-637), that it is final
// (ContextualCheckTransactionForCurrentBlock, validation.cpp:5955-5990),
// that it is not a confiscation transaction, whose whitelist Verify cannot
// see, and that the outputs it spends exist, are mature if they are a
// coinbase's or a confiscation transaction's, and their amounts cover what
// it pays (Consensus::CheckTxInputs, validation.cpp:2563-2655), and then its
// scripts.
func (g *txGraph) verifyTx(tx *transaction.Transaction, heights scriptflag.ActivationHeights) error {
	txid := g.txids[tx]

	// CheckRegularTransaction (validation.cpp:604-609): a transaction that
	// looks like a coinbase (one input spending the null outpoint) can only
	// be valid as a block's first transaction, which Verify never reaches
	// for an unmined transaction.
	if isCoinbase(tx) {
		return fmt.Errorf("%w: %s", ErrUnminedCoinbase, txid)
	}

	// CheckTransactionCommon (validation.cpp:525-533).
	if len(tx.Inputs) == 0 {
		return fmt.Errorf("%w: %s", ErrNoInputs, txid)
	}
	if len(tx.Outputs) == 0 {
		return fmt.Errorf("%w: %s", ErrNoOutputs, txid)
	}

	var outputTotal uint64
	for vout, output := range tx.Outputs {
		var ok bool
		if outputTotal, ok = addSatoshis(outputTotal, output.Satoshis); !ok {
			return fmt.Errorf("%w: output %d of %s", ErrValueOutOfRange, vout, txid)
		}
	}

	// A block after Genesis, as the next block always is here, rejects a
	// transaction that creates a P2SH output (CheckRegularTransaction,
	// validation.cpp:610-623). Without this, a pre-Genesis transaction
	// presented without its merkle path would pass as unmined, and its P2SH
	// outputs would count as created after Chronicle and be spendable with
	// the redeem script alone.
	if unminedHeight >= heights.Genesis {
		for vout, output := range tx.Outputs {
			if output.LockingScript != nil && output.LockingScript.IsP2SH() {
				return fmt.Errorf("%w: output %d of %s", ErrP2SHOutput, vout, txid)
			}
		}
	}

	// CheckRegularTransaction (validation.cpp:625-637): no input may spend
	// the null outpoint, and no outpoint may be spent twice.
	spent := make(map[outpoint]struct{}, len(tx.Inputs))
	for vin, input := range tx.Inputs {
		if isNullOutpoint(input) {
			return fmt.Errorf("%w: input %d of %s", ErrNullOutpoint, vin, txid)
		}
		op := outpoint{*input.SourceTXID, input.SourceTxOutIndex}
		if _, ok := spent[op]; ok {
			return fmt.Errorf("%w: input %d of %s spends %s:%d again", ErrDuplicateInput, vin, txid, op.txid, op.vout)
		}
		spent[op] = struct{}{}
	}

	// ContextualCheckTransactionForCurrentBlock (validation.cpp:5955-5990):
	// tx must be final for the block it would be mined in next.
	if err := g.txFinal(tx, txid); err != nil {
		return err
	}

	// Consensus::CheckTxInputs (validation.cpp:2563-2587): a confiscation
	// transaction is valid only if it is on the node's confiscation
	// whitelist, which Verify cannot see.
	if isConfiscationTx(tx) {
		return fmt.Errorf("%w: %s", ErrConfiscationTransaction, txid)
	}

	// Consensus::CheckTxInputs (validation.cpp:2590-2655): the output each
	// input spends must exist, a coinbase's or confiscation transaction's
	// output must be mature, and amounts must stay in range.
	prevouts := make([]*transaction.TransactionOutput, len(tx.Inputs))
	var inputTotal uint64
	for vin, input := range tx.Inputs {
		prevout := spentOutput(input)
		if prevout == nil {
			return fmt.Errorf("%w: input %d of %s", ErrMissingSourceTransaction, vin, txid)
		}
		prevouts[vin] = prevout

		mature, err := g.coinbaseMature(input)
		if err != nil {
			return err
		}
		if !mature {
			return fmt.Errorf("%w: input %d of %s", ErrPrematureCoinbaseSpend, vin, txid)
		}
		if mature, err = g.confiscationMature(input); err != nil {
			return err
		}
		if !mature {
			return fmt.Errorf("%w: input %d of %s", ErrPrematureConfiscationSpend, vin, txid)
		}

		var ok bool
		if inputTotal, ok = addSatoshis(inputTotal, prevout.Satoshis); !ok {
			return fmt.Errorf("%w: input %d of %s", ErrValueOutOfRange, vin, txid)
		}
	}
	if outputTotal > inputTotal {
		return fmt.Errorf("%w: %s pays %d satoshis and spends %d", ErrOutputsExceedInputs, txid, outputTotal, inputTotal)
	}

	for vin, input := range tx.Inputs {
		// tx is unmined: verify the input with the flags the node applies
		// when mining it in the next block. The spent output's era follows
		// the block height a verified merkle path proves for its source
		// transaction; an output whose source transaction is not proven
		// mined is taken as unmined, except a P2SH-shaped output, which
		// p2shCoinHeight forces pre-Genesis unless its source is a
		// proven-mined coinbase.
		coinHeight := uint32(unminedHeight)
		if height, ok := g.heights[*input.SourceTXID]; ok {
			coinHeight = height
		}
		coinHeight = g.p2shCoinHeight(input, prevouts[vin], coinHeight, heights)
		if err := interpreter.NewEngine().Execute(
			interpreter.WithTx(tx, vin, prevouts[vin]),
			interpreter.WithFlags(heights.BlockValidationFlags(coinHeight, unminedHeight)),
			interpreter.WithContext(g.ctx),
		); err != nil {
			// Wrapping with two %w verbs keeps both errors.Is targets live:
			// errors.Is(err, ErrScriptVerificationFailed) for any script
			// failure, and errors.Is(err, context.DeadlineExceeded) (or
			// context.Canceled) when the interpreter stopped because g.ctx
			// is done, via the interpreter error's own Unwrap.
			return fmt.Errorf("%w: %w", ErrScriptVerificationFailed, err)
		}
	}
	return nil
}

// p2shCoinHeight forces coinHeight to a pre-Genesis height when prevout is
// pay-to-script-hash-shaped (script.Script.IsP2SH, the exact 23-byte
// template) and input's source cannot be known to be a coinbase proven
// mined at coinHeight: CheckRegularTransaction rejects every non-coinbase
// transaction that creates a P2SH output after Genesis
// (validation.cpp:610-623), and CheckCoinbase applies no such restriction
// (validation.cpp:569-588), so a P2SH-shaped output that is not a
// proven-mined coinbase's output can only be a coin that existed before
// Genesis. This covers an EF input (no SourceTransaction), a source that is
// not proven mined, and a source "proven" at a height at or after Genesis,
// which is only possible with a forged merkle path (VerifyScripts'
// GullibleHeadersClient, for example): coinHeight becomes
// min(coinHeight, heights.Genesis-1). The zero ActivationHeights, which has
// no pre-Genesis era, is left unchanged.
func (g *txGraph) p2shCoinHeight(input *transaction.TransactionInput, prevout *transaction.TransactionOutput, coinHeight uint32, heights scriptflag.ActivationHeights) uint32 {
	if heights.Genesis == 0 {
		return coinHeight
	}
	if prevout.LockingScript == nil || !prevout.LockingScript.IsP2SH() {
		return coinHeight
	}
	if src := input.SourceTransaction; src != nil && isCoinbase(src) {
		if _, proven := g.heights[*input.SourceTXID]; proven {
			return coinHeight
		}
	}
	if coinHeight >= heights.Genesis {
		return heights.Genesis - 1
	}
	return coinHeight
}

// txFinal returns nil when tx would be final in the block mined after the
// chain tip (IsFinalTx, validation.cpp:228-248, called by
// ContextualCheckTransactionForCurrentBlock with tip+1 for a height-based
// lock and the tip's median time past for a time-based one), and otherwise a
// non-nil error wrapping ErrNonFinalTransaction. A transaction with no
// nLockTime, or whose inputs are all sequence-final, is always final: only
// then does nLockTime matter. BIP68 relative sequence locks are off after
// Genesis (StandardNonFinalVerifyFlags, policy.h) and are not implemented.
// It is skipped for a tracker without a real chain tip.
func (g *txGraph) txFinal(tx *transaction.Transaction, txid chainhash.Hash) error {
	if g.skipChainTip || tx.LockTime == 0 {
		return nil
	}
	nonFinalInput := false
	for _, input := range tx.Inputs {
		if input.SequenceNumber != transaction.DefaultSequenceNumber {
			nonFinalInput = true
			break
		}
	}
	if !nonFinalInput {
		return nil
	}
	if tx.LockTime >= lockTimeThreshold {
		// A time-based lock needs the tip's median time past, which only a
		// MedianTimePastProvider reports.
		mtp, ok, err := g.medianTimePast()
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: %s: nLockTime %d is time-based and chainTracker does not implement MedianTimePastProvider", ErrNonFinalTransaction, txid, tx.LockTime)
		}
		if tx.LockTime < mtp {
			return nil
		}
		return fmt.Errorf("%w: %s: nLockTime %d has not passed median time past %d", ErrNonFinalTransaction, txid, tx.LockTime, mtp)
	}
	tip, err := g.tip()
	if err != nil {
		return err
	}
	// In int64, so that a tip of math.MaxUint32 does not wrap tip+1. A
	// tracker that trails the chain makes an nLockTime set to the latest
	// height look non-final, as it would to a node that has not yet seen
	// that block.
	if int64(tx.LockTime) <= int64(tip) {
		return nil
	}
	return fmt.Errorf("%w: %s: nLockTime %d has not been reached by tip+1 (tip %d)", ErrNonFinalTransaction, txid, tx.LockTime, tip)
}

// medianTimePast returns the chain tip's median time past and true, fetched
// at most once per Verify call, or false when chainTracker does not report
// it.
func (g *txGraph) medianTimePast() (uint32, bool, error) {
	if g.mtpProvider == nil {
		return 0, false, nil
	}
	if g.mtp != nil {
		return *g.mtp, true, nil
	}
	mtp, err := g.mtpProvider.MedianTimePast(g.ctx)
	if err != nil {
		return 0, false, err
	}
	g.mtp = &mtp
	return mtp, true, nil
}

// coinbaseMature reports whether input may spend its source output:
// Consensus::CheckTxInputs (validation.cpp:2617-2625) requires a coinbase
// output to be at least coinbaseMaturity blocks deep, using signed
// arithmetic since a forged merkle path could claim a height past the tip.
// An input is only known to spend a coinbase when it carries its source
// transaction, so an EF input cannot be checked and is trusted, as the rest
// of what it supplies is (see Verify's doc comment). A coinbase source that
// is not proven mined is premature, since its depth cannot be known.
// It is skipped for a tracker without a real chain tip.
func (g *txGraph) coinbaseMature(input *transaction.TransactionInput) (bool, error) {
	src := input.SourceTransaction
	if src == nil || !isCoinbase(src) {
		return true, nil
	}
	return g.deepEnough(input, coinbaseMaturity)
}

// confiscationMature reports whether input may spend its source output:
// Consensus::CheckTxInputs (validation.cpp:2628-2636) requires an output of
// a confiscation transaction to be at least confiscationMaturity blocks deep.
// A coin is a confiscation coin when the transaction that created it is a
// confiscation transaction, coinbase or not (UpdateCoins,
// validation.cpp:2495). As with coinbaseMature, an EF input is trusted, a
// source not proven mined is premature, and the check is skipped for a
// tracker without a real chain tip.
func (g *txGraph) confiscationMature(input *transaction.TransactionInput) (bool, error) {
	src := input.SourceTransaction
	if src == nil || !isConfiscationTx(src) {
		return true, nil
	}
	return g.deepEnough(input, confiscationMaturity)
}

// deepEnough reports whether input's source transaction is proven mined at
// least maturity blocks below the block after the chain tip, for
// coinbaseMature and confiscationMature.
func (g *txGraph) deepEnough(input *transaction.TransactionInput, maturity int64) (bool, error) {
	if g.skipChainTip {
		return true, nil
	}
	height, proven := g.heights[*input.SourceTXID]
	if !proven {
		return false, nil
	}
	tip, err := g.tip()
	if err != nil {
		return false, err
	}
	return int64(tip)+1-int64(height) >= maturity, nil
}

// confiscationMarker is what a confiscation transaction's output 0 starts
// with: OP_FALSE OP_RETURN OP_PUSHDATA(4) 'cftx'.
var confiscationMarker = []byte{0x00, 0x6a, 0x04, 'c', 'f', 't', 'x'}

// isConfiscationTx is bitcoin-sv's test for a confiscation transaction:
// output 0's locking script starts with confiscationMarker
// (CFrozenTXODB::IsConfiscationTx, frozentxo_db.cpp:614-634).
func isConfiscationTx(tx *transaction.Transaction) bool {
	if len(tx.Outputs) == 0 || tx.Outputs[0] == nil || tx.Outputs[0].LockingScript == nil {
		return false
	}
	return bytes.HasPrefix(*tx.Outputs[0].LockingScript, confiscationMarker)
}

// isNullOutpoint reports whether input spends the null outpoint: a zero
// txid and index 0xffffffff (COutPoint::IsNull, primitives/transaction.h).
func isNullOutpoint(input *transaction.TransactionInput) bool {
	return *input.SourceTXID == (chainhash.Hash{}) && input.SourceTxOutIndex == transaction.DefaultSequenceNumber
}

// isCoinbase is bitcoin-sv's exact test for a coinbase transaction: exactly
// one input, spending the null outpoint (CTransaction::IsCoinBase,
// primitives/transaction.h:323-325). transaction.Transaction.IsCoinbase is
// not node-exact — it also accepts an ordinary outpoint index when
// SequenceNumber is 0xffffffff — so it must not be used here.
func isCoinbase(tx *transaction.Transaction) bool {
	return len(tx.Inputs) == 1 && isNullOutpoint(tx.Inputs[0])
}

// spentOutput returns the output input spends: the output of its source
// transaction when it carries one, which a source transaction without that
// output leaves missing, and otherwise the output supplied with
// SetSourceTxOutput.
func spentOutput(input *transaction.TransactionInput) *transaction.TransactionOutput {
	src := input.SourceTransaction
	if src == nil {
		return input.SourceTxOutput()
	}
	if int64(input.SourceTxOutIndex) >= int64(len(src.Outputs)) {
		return nil
	}
	return src.Outputs[input.SourceTxOutIndex]
}

// addSatoshis adds amount to total, a total within the money range, and
// reports whether amount and the sum are both within it (MoneyRange,
// amount.h:132).
func addSatoshis(total, amount uint64) (uint64, bool) {
	if amount > maxSatoshis || total > maxSatoshis-amount {
		return 0, false
	}
	return total + amount, true
}
