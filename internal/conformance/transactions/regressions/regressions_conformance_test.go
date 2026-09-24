// Package regressions_test runs the ts-stack conformance vectors for the
// transaction-domain regression files (beef-isvalid-hydration,
// beef-v2-txid-panic, fee-model-mismatch, merkle-path-odd-node,
// tx-sequence-zero-sighash), mirroring the assertions made by
// conformance/runner/ts/dispatchers/regressions.ts (and sdk.ts for
// beef-v2-txid-panic, which it documents as routed to the sdk dispatcher) in
// ts-stack.
package regressions_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// ── beef-isvalid-hydration ──────────────────────────────────────────────────

type beefHydrationIn struct {
	BeefHex   string `json:"beef_hex"`
	Operation string `json:"operation"`
}

type beefHydrationExp struct {
	IsValid     bool `json:"is_valid"`
	TxidNonNull bool `json:"txid_non_null"`
}

func TestBeefIsValidHydrationConformance(t *testing.T) {
	file := conformance.Load(t, "regressions/beef-isvalid-hydration.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in beefHydrationIn
		v.DecodeInput(t, &in)
		var exp beefHydrationExp
		v.DecodeExpected(t, &exp)

		switch in.Operation {
		case "NewBeefFromBytes_IsValid":
			beef, err := transaction.NewBeefFromHex(in.BeefHex)
			require.NoError(t, err)
			require.Equal(t, exp.IsValid, beef.IsValid(true))

		case "NewTransactionFromBEEFHex_TxID":
			tx, err := transaction.NewTransactionFromBEEFHex(in.BeefHex)
			require.NoError(t, err)
			require.Equal(t, exp.TxidNonNull, tx.TxID() != nil)

		default:
			t.Fatalf("unhandled operation %q for vector %q", in.Operation, v.ID)
		}
	})
}

// ── beef-v2-txid-panic ───────────────────────────────────────────────────────

type beefV2In struct {
	BeefHex string `json:"beef_hex"`
	Format  string `json:"format"`
}

type beefV2Exp struct {
	ParseSucceeds bool `json:"parse_succeeds"`
	TxidNonNull   bool `json:"txid_non_null"`
}

func TestBeefV2TxidPanicConformance(t *testing.T) {
	file := conformance.Load(t, "regressions/beef-v2-txid-panic.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in beefV2In
		v.DecodeInput(t, &in)
		var exp beefV2Exp
		v.DecodeExpected(t, &exp)

		beefBytes, err := hex.DecodeString(in.BeefHex)
		require.NoError(t, err)

		// ParseBeef must not panic on a transaction-less BEEF envelope (the
		// go-sdk#306 regression: BEEF_V2 parsing returned a nil *Transaction,
		// and callers who called .TxID() on it without a nil check panicked).
		_, tx, _, err := transaction.ParseBeef(beefBytes)
		if !exp.ParseSucceeds {
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
		if exp.TxidNonNull {
			require.NotNil(t, tx)
			require.NotNil(t, tx.TxID())
		} else {
			require.Nil(t, tx, "no transactions in the envelope: ParseBeef must return a nil "+
				"*Transaction rather than one whose TxID() panics")
		}
	})
}

// ── fee-model-mismatch ───────────────────────────────────────────────────────

type feeModelIn struct {
	Operation     string `json:"operation"`
	SizeBytes     int    `json:"size_bytes"`
	SatoshisPerKb uint64 `json:"satoshis_per_kb"`
}

func TestFeeModelMismatchConformance(t *testing.T) {
	file := conformance.Load(t, "regressions/fee-model-mismatch.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in feeModelIn
		v.DecodeInput(t, &in)
		require.Equal(t, "compute_fee", in.Operation)

		// Maintainer decision pending: go-sdk's SatoshisPerKilobyte.ComputeFee
		// must stay identical to ts-sdk's SatoshisPerKilobyte.computeFee, which
		// uses Math.ceil((size / 1000) * rate) -- see
		// ts-stack/packages/sdk/src/transaction/fee-models/SatoshisPerKilobyte.ts
		// and this vector file's own description, which states in so many
		// words that "The ts-sdk uses ceil(size/1000 * rate) which is also not
		// identical to node but closer." The vector's expected fee_satoshis is
		// instead the BSV node's floor(size*rate/1000) formula, computed by a
		// local bsvNodeFee() helper in ts-stack's own
		// conformance/runner/ts/dispatchers/regressions.ts
		// (dispatchFeeModelMismatch) -- it never calls the TS SDK's
		// SatoshisPerKilobyte. Per policy P4(a), Go production code (and its
		// unexported calculateFee) must not be changed to chase a formula the
		// SDK conformance corpus itself documents as SDK-divergent; matching
		// the node formula instead of ts-sdk would break parity with the
		// actual TS reference SDK we're conforming to. Tracked as a GoGap
		// pending a maintainer decision on whether go-sdk/ts-sdk should ever
		// adopt the node-exact formula.
		conformance.GoGap(t, "maintainer decision pending: go-sdk SatoshisPerKilobyte "+
			"intentionally matches ts-sdk's ceil(size/1000*rate) formula, not this "+
			"vector's BSV-node floor(size*rate/1000) formula, which the TS runner "+
			"computes locally (bsvNodeFee) without calling the TS SDK; see "+
			"ts-stack/packages/sdk/src/transaction/fee-models/SatoshisPerKilobyte.ts "+
			"and this file's own description field")
	})
}

// ── merkle-path-odd-node ─────────────────────────────────────────────────────

type merkleOddNodeIn struct {
	Operation string `json:"operation"`
	LeftHex   string `json:"left_hex"`
	RightHex  string `json:"right_hex"`
}

type merkleOddNodeExp struct {
	ParentHex string `json:"parent_hex"`
}

func TestMerklePathOddNodeConformance(t *testing.T) {
	file := conformance.Load(t, "regressions/merkle-path-odd-node.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in merkleOddNodeIn
		v.DecodeInput(t, &in)
		var exp merkleOddNodeExp
		v.DecodeExpected(t, &exp)

		require.Equal(t, "merkle_tree_parent", in.Operation)

		leftBytes, err := hex.DecodeString(in.LeftHex)
		require.NoError(t, err)
		rightBytes, err := hex.DecodeString(in.RightHex)
		require.NoError(t, err)
		left, err := chainhash.NewHash(leftBytes)
		require.NoError(t, err)
		right, err := chainhash.NewHash(rightBytes)
		require.NoError(t, err)

		// MerkleTreeParent takes and returns raw (non-reversed) bytes — the
		// vectors' left_hex/right_hex/parent_hex are literal, non-display-order
		// hash256 inputs/outputs (see transaction.MerkleTreeParent's doc
		// comment), so we encode the result directly rather than through
		// chainhash.Hash.String() (which reverses for txid-style display).
		parent := transaction.MerkleTreeParent(left, right)
		require.Equal(t, exp.ParentHex, hex.EncodeToString(parent[:]))
	})
}

// ── tx-sequence-zero-sighash ─────────────────────────────────────────────────

type txSequenceZeroIn struct {
	Operation     string `json:"operation"`
	Version       uint32 `json:"version"`
	InputSequence uint32 `json:"input_sequence"`
	LockTime      uint32 `json:"lock_time"`
	SighashType   string `json:"sighash_type"`
}

type txSequenceZeroExp struct {
	PreimageSequenceFieldHex string `json:"preimage_sequence_field_hex"`
	SerialisedSequenceHex    string `json:"serialised_sequence_hex"`
}

// buildMinimalInputTx mirrors the TS regression's minimal preimage params: a
// single input spending a zero txid/index/value output with an empty
// subscript, so the BIP143 preimage's nSequence field lands at the fixed
// offset 4(version)+32(hashPrevouts)+32(hashSequence)+32(outpoint hash)+
// 4(outpoint index)+1(empty-script varint)+0(script)+8(value) = 113.
func buildMinimalInputTx(t *testing.T, version, sequence, lockTime uint32) *transaction.Transaction {
	t.Helper()
	zero, err := chainhash.NewHash(make([]byte, chainhash.HashSize))
	require.NoError(t, err)

	sourceTx := transaction.NewTransaction()
	sourceTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      0,
		LockingScript: &script.Script{},
	})

	tx := transaction.NewTransaction()
	tx.Version = version
	tx.LockTime = lockTime
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:        zero,
		SourceTxOutIndex:  0,
		SourceTransaction: sourceTx,
		SequenceNumber:    sequence,
		UnlockingScript:   &script.Script{},
	})
	return tx
}

func TestTxSequenceZeroSighashConformance(t *testing.T) {
	file := conformance.Load(t, "regressions/tx-sequence-zero-sighash.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in txSequenceZeroIn
		v.DecodeInput(t, &in)
		var exp txSequenceZeroExp
		v.DecodeExpected(t, &exp)

		switch in.Operation {
		case "sighash_preimage":
			require.Equal(t, "SIGHASH_ALL", in.SighashType)
			tx := buildMinimalInputTx(t, in.Version, in.InputSequence, in.LockTime)
			preimage, err := tx.CalcInputPreimage(0, sighash.AllForkID)
			require.NoError(t, err)
			const seqOffset = 4 + 32 + 32 + 32 + 4 + 1 + 0 + 8
			require.Equal(t, exp.PreimageSequenceFieldHex, hex.EncodeToString(preimage[seqOffset:seqOffset+4]))

		case "serialise_input_sequence":
			tx := buildMinimalInputTx(t, 1, in.InputSequence, 0)
			raw := tx.Bytes()
			const seqOffset = 4 + 1 + 32 + 4 + 1
			require.Equal(t, exp.SerialisedSequenceHex, hex.EncodeToString(raw[seqOffset:seqOffset+4]))

		default:
			t.Fatalf("unhandled operation %q for vector %q", in.Operation, v.ID)
		}
	})
}
