// Package serialization_test runs the ts-stack conformance vectors for
// sdk/transactions/serialization.json against go-sdk's Transaction, Beef and
// MerklePath types, mirroring the TS reference runner's dispatchSerialization
// and dispatchSerializationOp (conformance/runner/ts/dispatchers/sdk.ts /
// sdkHelpers.ts in ts-stack).
package serialization_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// serIn is a superset decode target covering every input shape used by
// sdk/transactions/serialization.json's vectors.
type serIn struct {
	Operation         string `json:"operation"`
	RawHex            string `json:"raw_hex"`
	BeefHex           string `json:"beef_hex"`
	EfHex             string `json:"ef_hex"`
	BumpHex           string `json:"bump_hex"`
	SourceTxid        string `json:"source_txid"`
	SourceOutputIndex uint32 `json:"source_output_index"`
}

// serExp is a superset decode target covering every expectation shape.
type serExp struct {
	RawHexRoundtrip string  `json:"raw_hex_roundtrip"`
	Version         *uint32 `json:"version"`
	InputsCount     *int    `json:"inputs_count"`
	OutputsCount    *int    `json:"outputs_count"`
	Locktime        *uint32 `json:"locktime"`
	Txid            string  `json:"txid"`
	MerkleRoot      string  `json:"merkle_root"`
	Throws          bool    `json:"throws"`
	Sequence        *uint32 `json:"sequence"`
	HashLengthChars *int    `json:"hash_length_chars"`
	IDLengthBytes   *int    `json:"id_length_bytes"`
	BlockHeight     *uint32 `json:"block_height"`
	PathLeafCount   *int    `json:"path_leaf_count"`
}

func TestSerializationConformance(t *testing.T) {
	file := conformance.Load(t, "sdk/transactions/serialization.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in serIn
		v.DecodeInput(t, &in)
		var exp serExp
		v.DecodeExpected(t, &exp)

		switch v.ID {
		case "tx-001", "tx-002", "tx-015":
			tx, err := transaction.NewTransactionFromHex(in.RawHex)
			require.NoError(t, err)
			if exp.Version != nil {
				require.Equal(t, *exp.Version, tx.Version)
			}
			if exp.InputsCount != nil {
				require.Len(t, tx.Inputs, *exp.InputsCount)
			}
			if exp.OutputsCount != nil {
				require.Len(t, tx.Outputs, *exp.OutputsCount)
			}
			if exp.Locktime != nil {
				require.Equal(t, *exp.Locktime, tx.LockTime)
			}
			if exp.Txid != "" {
				require.Equal(t, exp.Txid, tx.TxID().String())
			}
			if exp.RawHexRoundtrip != "" {
				require.Equal(t, exp.RawHexRoundtrip, hex.EncodeToString(tx.Bytes()))
			}

		case "tx-003":
			beef, err := transaction.NewBeefFromHex(in.BeefHex)
			require.NoError(t, err)
			require.NotEmpty(t, beef.BUMPs)
			root, err := beef.BUMPs[0].ComputeRoot(nil)
			require.NoError(t, err)
			require.Equal(t, exp.MerkleRoot, root.String())

		case "tx-004":
			// go-sdk's Transaction reader auto-detects the BRC-30 Extended
			// Format marker (0xEF) inline in NewTransactionFromHex, so there
			// is no separate FromHexEF entry point to call (unlike ts-sdk's
			// Transaction.fromHexEF).
			tx, err := transaction.NewTransactionFromHex(in.EfHex)
			require.NoError(t, err)
			require.Len(t, tx.Inputs, *exp.InputsCount)
			require.Len(t, tx.Outputs, *exp.OutputsCount)

		case "tx-005":
			tx := transaction.NewTransaction()
			require.Equal(t, *exp.Version, tx.Version)
			require.Len(t, tx.Inputs, *exp.InputsCount)
			require.Len(t, tx.Outputs, *exp.OutputsCount)
			require.Equal(t, *exp.Locktime, tx.LockTime)

		case "tx-006":
			// Transaction.fromAtomicBEEF (BRC-95) must reject a beef that
			// isn't wrapped in the Atomic BEEF envelope. NewBeefFromAtomicBytes
			// is go-sdk's atomic-only entry point (NewTransactionFromBEEF
			// would happily accept this as a plain BEEF_V1 payload instead,
			// which is not what this vector exercises).
			require.True(t, exp.Throws)
			beefBytes, err := hex.DecodeString(in.BeefHex)
			require.NoError(t, err)
			_, _, err = transaction.NewBeefFromAtomicBytes(beefBytes)
			require.Error(t, err)

		case "tx-007":
			conformance.GoGap(t, "transaction.AddInput takes a fully-built *TransactionInput and never "+
				"validates or errors (it is an unchecked append); go-sdk has no throwing equivalent of "+
				"ts-sdk's addInput({}) reference-required check")

		case "tx-008":
			tx := transaction.NewTransaction()
			err := tx.AddInputFrom(in.SourceTxid, in.SourceOutputIndex, "", 0, nil)
			require.NoError(t, err)
			require.Equal(t, *exp.Sequence, tx.Inputs[0].SequenceNumber)

		case "tx-009", "tx-010":
			conformance.GoGap(t, "transaction.AddOutput takes a fully-built *TransactionOutput and never "+
				"validates or errors, and TransactionOutput.Satoshis is a uint64 so negative satoshis "+
				"cannot even be represented; go-sdk has no throwing equivalent of ts-sdk's addOutput checks")

		case "tx-011":
			tx := transaction.NewTransaction()
			require.Len(t, tx.TxID().String(), *exp.HashLengthChars)

		case "tx-012":
			tx := transaction.NewTransaction()
			txid := tx.TxID()
			require.Len(t, txid[:], *exp.IDLengthBytes)

		case "tx-013":
			mp, err := transaction.NewMerklePathFromHex(in.BumpHex)
			require.NoError(t, err)
			require.Equal(t, *exp.BlockHeight, mp.BlockHeight)
			require.Len(t, mp.Path[0], *exp.PathLeafCount)

		case "tx-014":
			tx := transaction.NewTransaction()
			srcTxid, err := chainhash.NewHashFromHex(in.SourceTxid)
			require.NoError(t, err)
			tx.AddInput(&transaction.TransactionInput{
				SourceTXID:       srcTxid,
				SourceTxOutIndex: in.SourceOutputIndex,
				SequenceNumber:   transaction.DefaultSequenceNumber,
			})
			_, err = tx.GetFee()
			require.Error(t, err)

		default:
			t.Fatalf("unhandled vector id %q", v.ID)
		}
	})
}
