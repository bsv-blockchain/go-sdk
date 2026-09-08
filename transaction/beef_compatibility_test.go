package transaction

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
)

func TestBeefVersionRoundTripFromTSIdentity(t *testing.T) {
	data, err := os.ReadFile("testdata/beef-compatibility/identity.json")
	require.NoError(t, err)
	var fixture struct {
		BeefBase64   string `json:"beefBase64"`
		BeefSHA256   string `json:"beefSha256"`
		AtomicBase64 string `json:"atomicBEEFBase64"`
		TxID         string `json:"txid"`
		MerkleRoot   string `json:"merkleRoot"`
	}
	require.NoError(t, json.Unmarshal(data, &fixture))
	raw, err := base64.StdEncoding.DecodeString(fixture.BeefBase64)
	require.NoError(t, err)
	digest := sha256.Sum256(raw)
	require.Equal(t, fixture.BeefSHA256, hex.EncodeToString(digest[:]))
	id, err := chainhash.NewHashFromHex(fixture.TxID)
	require.NoError(t, err)
	b, err := NewBeefFromBytes(raw)
	require.NoError(t, err)
	require.Equal(t, BEEF_V1, b.Version)
	serialized, err := b.Bytes()
	require.NoError(t, err)
	require.Equal(t, raw, serialized, "real TS V1 bytes must retain their V1 transaction layout")
	atomic, err := b.AtomicBytes(id)
	require.NoError(t, err)
	require.Equal(t, BEEF_V1, binary.LittleEndian.Uint32(atomic[36:40]))
	parsed, target, err := NewBeefFromAtomicBytes(atomic)
	require.NoError(t, err)
	require.Equal(t, id, target)
	require.Equal(t, id, parsed.NewestTxID)
	tx := parsed.FindTransactionByHash(target)
	require.NotNil(t, tx)
	require.Equal(t, fixture.TxID, tx.TxID().String())
	root, err := tx.MerklePath.ComputeRoot(tx.TxID())
	require.NoError(t, err)
	require.Equal(t, fixture.MerkleRoot, root.String())
	tsAtomic, err := base64.StdEncoding.DecodeString(fixture.AtomicBase64)
	require.NoError(t, err)
	require.Equal(t, tsAtomic, atomic, "Go AtomicBytes must match the exact signed TS fixture")
	original, originalTarget, err := NewBeefFromAtomicBytes(tsAtomic)
	require.NoError(t, err)
	require.Equal(t, id, originalTarget)
	require.Equal(t, tx.Bytes(), original.FindTransactionByHash(id).Bytes())
	require.Equal(t, BEEF_V1, b.Version, "AtomicBytes must not upgrade the caller")
}

func TestBeefAtomicSelectionPreservesCallerAndProofs(t *testing.T) {
	for _, version := range []uint32{BEEF_V1, BEEF_V2} {
		t.Run(fmt.Sprintf("%x", version), func(t *testing.T) {
			parent := benchTx(11)
			left := benchTx(12, parent)
			right := benchTx(13, parent)
			subject := benchTx(14, left, right)
			unrelated := benchTx(15)
			b := newEmptyBeef(version)
			for _, tx := range []*Transaction{subject, unrelated, right, parent, left} {
				_, err := b.MergeRawTx(tx.Bytes(), nil)
				require.NoError(t, err)
			}
			b.NewestTxID = unrelated.TxID()
			levels := benchMerkleTree([]*chainhash.Hash{parent.TxID(), unrelated.TxID()})
			first := benchProofBUMP(100, levels, 0)
			variant := benchProofBUMP(101, levels, 0)
			b.BUMPs = []*MerklePath{first, variant}
			entry := b.Transactions[*parent.TxID()]
			entry.DataFormat, entry.BumpIndex = RawTxAndBumpIndex, 1
			before := variant.Bytes()
			atomic, err := b.AtomicBytes(subject.TxID())
			require.NoError(t, err)
			parsed, target, err := NewBeefFromAtomicBytes(atomic)
			require.NoError(t, err)
			require.Equal(t, subject.TxID(), target)
			require.Len(t, parsed.Transactions, 4)
			require.NotContains(t, parsed.Transactions, *unrelated.TxID())
			require.Len(t, parsed.BUMPs, 1)
			require.Equal(t, before, parsed.BUMPs[0].Bytes())
			require.Equal(t, 0, parsed.Transactions[*parent.TxID()].BumpIndex)
			tx := parsed.FindTransactionByHash(target)
			require.Equal(t, subject.Bytes(), tx.Bytes())
			require.Same(t, tx.Inputs[0].SourceTransaction.Inputs[0].SourceTransaction,
				tx.Inputs[1].SourceTransaction.Inputs[0].SourceTransaction, "shared ancestor is linked once")
			require.Equal(t, version, b.Version)
			require.Equal(t, unrelated.TxID(), b.NewestTxID)
			require.Len(t, b.Transactions, 5)
			require.Same(t, entry, b.Transactions[*parent.TxID()])
			require.Equal(t, 1, entry.BumpIndex)
			require.Same(t, variant, b.BUMPs[1])
			require.Equal(t, before, variant.Bytes())
		})
	}
}

func TestBeefVersionAndEntryErrors(t *testing.T) {
	b := NewBeefV1()
	parent := benchTx(1)
	b.MergeTxidOnly(parent.TxID())
	_, err := b.Bytes()
	require.ErrorContains(t, err, "V1 cannot serialize txid-only")
	_, err = b.AtomicBytes(parent.TxID())
	require.ErrorContains(t, err, "V1 cannot serialize txid-only")
	require.Equal(t, BEEF_V1, b.Version)
	b.Version = BEEF_V2
	atomic, err := b.AtomicBytes(parent.TxID())
	require.NoError(t, err)
	parsed, target, err := NewBeefFromAtomicBytes(atomic)
	require.NoError(t, err)
	require.Equal(t, parent.TxID(), target)
	require.Nil(t, parsed.Transactions[*target].Transaction)
	_, err = NewTransactionFromBEEF(atomic)
	require.ErrorContains(t, err, "raw subject")
	b.Version = 0
	_, err = b.Bytes()
	require.ErrorContains(t, err, "version")
	b.Version = BEEF_V2
	b.Transactions[*parent.TxID()] = &BeefTx{DataFormat: RawTx, Transaction: benchTx(2)}
	_, err = b.Bytes()
	require.ErrorContains(t, err, "does not match")
	_, err = b.AtomicBytes(parent.TxID())
	require.ErrorContains(t, err, "does not match")
}

func TestBeefAtomicRejectsMissingSubject(t *testing.T) {
	b := NewBeefV2()
	_, err := b.AtomicBytes(nil)
	require.Error(t, err)
	id := benchTx(5).TxID()
	_, err = b.AtomicBytes(id)
	require.ErrorContains(t, err, "missing")
	empty, err := b.Bytes()
	require.NoError(t, err)
	atomic := append(bytes.Repeat([]byte{1}, 4), id[:]...)
	atomic = append(atomic, empty...)
	_, _, err = NewBeefFromAtomicBytes(atomic)
	require.ErrorContains(t, err, "missing")
	_, err = NewBeefFromBytes(atomic)
	require.ErrorContains(t, err, "missing")
	parsed, subject, target, err := ParseBeef(atomic)
	require.Nil(t, parsed)
	require.Nil(t, subject)
	require.Nil(t, target)
	require.ErrorContains(t, err, "missing")
	_, err = NewTransactionFromBEEF(atomic)
	require.ErrorContains(t, err, "missing")
}

func TestAtomicTransactionRetainsExplicitProofVariant(t *testing.T) {
	parent := benchTx(50)
	other := benchTx(51)
	levels := benchMerkleTree([]*chainhash.Hash{parent.TxID(), other.TxID()})
	b := NewBeefV2()
	b.BUMPs = []*MerklePath{benchProofBUMP(100, levels, 0), benchProofBUMP(101, levels, 0)}
	b.Transactions[*parent.TxID()] = &BeefTx{DataFormat: RawTxAndBumpIndex, Transaction: parent, BumpIndex: 1}
	inner, err := b.Bytes()
	require.NoError(t, err)
	// Preserve both proof variants in an externally supplied Atomic prefix.
	atomic := append(bytes.Repeat([]byte{1}, 4), parent.TxID()[:]...)
	atomic = append(atomic, inner...)
	tx, err := NewTransactionFromBEEF(atomic)
	require.NoError(t, err)
	require.Equal(t, b.BUMPs[1].Bytes(), tx.MerklePath.Bytes())
}

func TestParseBeefAtomicTxidOnlySubjectRequiresRawTransaction(t *testing.T) {
	b := NewBeefV2()
	id := benchTx(1).TxID()
	b.MergeTxidOnly(id)
	atomic, err := b.AtomicBytes(id)
	require.NoError(t, err)
	beef, tx, target, err := ParseBeef(atomic)
	require.ErrorContains(t, err, "raw subject")
	require.Nil(t, beef)
	require.Nil(t, tx)
	require.Nil(t, target)
}
