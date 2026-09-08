package transaction

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func malformedRawBumpBEEF(t *testing.T, bump *MerklePath, bumpIndex int) (*Beef, *chainhash.Hash) {
	t.Helper()
	tx := benchTx(1)
	txid := tx.TxID()
	beef := NewBeefV2()
	beef.BUMPs = []*MerklePath{bump}
	beef.Transactions[*txid] = &BeefTx{
		DataFormat:  RawTxAndBumpIndex,
		Transaction: tx,
		BumpIndex:   bumpIndex,
	}
	return beef, txid
}

func TestBeefSerializationRejectsMalformedRepresentations(t *testing.T) {
	validHash := chainhash.Hash{}
	validBUMP := &MerklePath{Path: [][]*PathElement{{&PathElement{Hash: &validHash}}}}
	tooManyLevels := make([][]*PathElement, 256)

	tests := []struct {
		name string
		new  func(t *testing.T) (*Beef, *chainhash.Hash)
	}{
		{
			name: "nil transaction entry",
			new: func(t *testing.T) (*Beef, *chainhash.Hash) {
				id := &chainhash.Hash{}
				beef := NewBeefV2()
				beef.Transactions[*id] = nil
				return beef, id
			},
		},
		{
			name: "invalid data format",
			new: func(t *testing.T) (*Beef, *chainhash.Hash) {
				id := &chainhash.Hash{}
				beef := NewBeefV2()
				beef.Transactions[*id] = &BeefTx{DataFormat: DataFormat(99)}
				return beef, id
			},
		},
		{
			name: "nil raw transaction",
			new: func(t *testing.T) (*Beef, *chainhash.Hash) {
				id := &chainhash.Hash{}
				beef := NewBeefV2()
				beef.Transactions[*id] = &BeefTx{DataFormat: RawTx}
				return beef, id
			},
		},
		{
			name: "missing known txid",
			new: func(t *testing.T) (*Beef, *chainhash.Hash) {
				id := &chainhash.Hash{}
				beef := NewBeefV2()
				beef.Transactions[*id] = &BeefTx{DataFormat: TxIDOnly}
				return beef, id
			},
		},
		{
			name: "nil transaction input",
			new: func(t *testing.T) (*Beef, *chainhash.Hash) {
				id := &chainhash.Hash{}
				beef := NewBeefV2()
				beef.Transactions[*id] = &BeefTx{DataFormat: RawTx, Transaction: &Transaction{Inputs: []*TransactionInput{nil}}}
				return beef, id
			},
		},
		{
			name: "nil input source txid",
			new: func(t *testing.T) (*Beef, *chainhash.Hash) {
				id := &chainhash.Hash{}
				beef := NewBeefV2()
				beef.Transactions[*id] = &BeefTx{DataFormat: RawTx, Transaction: &Transaction{Inputs: []*TransactionInput{{}}}}
				return beef, id
			},
		},
		{
			name: "nil transaction output",
			new: func(t *testing.T) (*Beef, *chainhash.Hash) {
				id := &chainhash.Hash{}
				beef := NewBeefV2()
				beef.Transactions[*id] = &BeefTx{DataFormat: RawTx, Transaction: &Transaction{Outputs: []*TransactionOutput{nil}}}
				return beef, id
			},
		},
		{
			name: "nil locking script",
			new: func(t *testing.T) (*Beef, *chainhash.Hash) {
				id := &chainhash.Hash{}
				beef := NewBeefV2()
				beef.Transactions[*id] = &BeefTx{DataFormat: RawTx, Transaction: &Transaction{Outputs: []*TransactionOutput{{}}}}
				return beef, id
			},
		},
		{
			name: "nil BUMP",
			new: func(t *testing.T) (*Beef, *chainhash.Hash) {
				return malformedRawBumpBEEF(t, nil, 0)
			},
		},
		{
			name: "nil BUMP leaf",
			new: func(t *testing.T) (*Beef, *chainhash.Hash) {
				return malformedRawBumpBEEF(t, &MerklePath{Path: [][]*PathElement{{nil}}}, 0)
			},
		},
		{
			name: "nil non-duplicate BUMP hash",
			new: func(t *testing.T) (*Beef, *chainhash.Hash) {
				return malformedRawBumpBEEF(t, &MerklePath{Path: [][]*PathElement{{&PathElement{}}}}, 0)
			},
		},
		{
			name: "zero BUMP path levels",
			new: func(t *testing.T) (*Beef, *chainhash.Hash) {
				return malformedRawBumpBEEF(t, &MerklePath{}, 0)
			},
		},
		{
			name: "too many BUMP path levels",
			new: func(t *testing.T) (*Beef, *chainhash.Hash) {
				return malformedRawBumpBEEF(t, &MerklePath{Path: tooManyLevels}, 0)
			},
		},
		{
			name: "negative BUMP index",
			new: func(t *testing.T) (*Beef, *chainhash.Hash) {
				return malformedRawBumpBEEF(t, validBUMP, -1)
			},
		},
		{
			name: "out of range BUMP index",
			new: func(t *testing.T) (*Beef, *chainhash.Hash) {
				return malformedRawBumpBEEF(t, validBUMP, 1)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			beef, subject := tt.new(t)
			assert.NotPanics(t, func() {
				_, err := beef.Bytes()
				require.Error(t, err)
			})
			assert.NotPanics(t, func() {
				_, err := beef.AtomicBytes(subject)
				require.Error(t, err)
			})
		})
	}
}

func TestBeefSerializationRejectsAliasedAndCyclicMaps(t *testing.T) {
	t.Run("aliased transaction under a second key", func(t *testing.T) {
		tx := benchTx(1)
		id := *tx.TxID()
		alias := id
		alias[0] ^= 0xff
		beef := NewBeefV2()
		entry := &BeefTx{DataFormat: RawTx, Transaction: tx}
		beef.Transactions[id] = entry
		beef.Transactions[alias] = entry
		assert.NotPanics(t, func() {
			_, err := beef.Bytes()
			require.ErrorContains(t, err, "does not match")
		})
		assert.NotPanics(t, func() {
			_, err := beef.AtomicBytes(&alias)
			require.ErrorContains(t, err, "does not match")
		})
	})

	t.Run("cycle-shaped map with noncanonical keys", func(t *testing.T) {
		firstID := chainhash.Hash{1}
		secondID := chainhash.Hash{2}
		first := &Transaction{Inputs: []*TransactionInput{{SourceTXID: &secondID}}}
		second := &Transaction{Inputs: []*TransactionInput{{SourceTXID: &firstID}}}
		beef := NewBeefV2()
		beef.Transactions[firstID] = &BeefTx{DataFormat: RawTx, Transaction: first}
		beef.Transactions[secondID] = &BeefTx{DataFormat: RawTx, Transaction: second}
		assert.NotPanics(t, func() {
			_, err := beef.Bytes()
			require.ErrorContains(t, err, "does not match")
		})
		assert.NotPanics(t, func() {
			_, err := beef.AtomicBytes(&firstID)
			require.ErrorContains(t, err, "does not match")
		})
	})
}

func TestBEEFDecoderCompatibilityWithSuffixesAndOverlongVarInts(t *testing.T) {
	for _, version := range []uint32{BEEF_V1, BEEF_V2} {
		t.Run("version", func(t *testing.T) {
			tx := benchTx(1)
			beef := newEmptyBeef(version)
			beef.Transactions[*tx.TxID()] = &BeefTx{DataFormat: RawTx, Transaction: tx}
			beef.NewestTxID = tx.TxID()
			canonical, err := beef.Bytes()
			require.NoError(t, err)

			withSuffix := append(append([]byte{}, canonical...), 0xde, 0xad)
			parsed, err := NewBeefFromBytes(withSuffix)
			require.NoError(t, err)
			normalized, err := parsed.Bytes()
			require.NoError(t, err)
			require.Equal(t, canonical, normalized)

			overlong := append([]byte{}, canonical[:4]...)
			overlong = append(overlong, 0xfd, 0x00, 0x00, 0xfd, 0x01, 0x00)
			overlong = append(overlong, canonical[6:]...)
			parsed, err = NewBeefFromBytes(overlong)
			require.NoError(t, err)
			normalized, err = parsed.Bytes()
			require.NoError(t, err)
			require.Equal(t, canonical, normalized)
		})
	}
}

func TestParseBeefEmptyV1AndRejectsNestedAtomicHeader(t *testing.T) {
	emptyV1, err := NewBeefV1().Bytes()
	require.NoError(t, err)
	var parsed *Beef
	var tx *Transaction
	var txid *chainhash.Hash
	assert.NotPanics(t, func() {
		parsed, tx, txid, err = ParseBeef(emptyV1)
	})
	require.NoError(t, err)
	require.NotNil(t, parsed)
	require.Equal(t, BEEF_V1, parsed.Version)
	require.Nil(t, tx)
	require.Nil(t, txid)

	nestedAtomic := binary.LittleEndian.AppendUint32(nil, ATOMIC_BEEF)
	nestedAtomic = append(nestedAtomic, make([]byte, chainhash.HashSize)...)
	nestedAtomic = binary.LittleEndian.AppendUint32(nestedAtomic, ATOMIC_BEEF)
	_, _, err = NewBeefFromAtomicBytes(nestedAtomic)
	require.Error(t, err)
	_, err = NewBeefFromBytes(nestedAtomic)
	require.Error(t, err)
	_, err = NewTransactionFromBEEF(nestedAtomic)
	require.Error(t, err)
}

func TestAtomicSelectionDoesNotTrustDuplicateLeafHash(t *testing.T) {
	parent := benchTx(1)
	subject := benchTx(2, parent)
	duplicate := true
	proof := &MerklePath{Path: [][]*PathElement{{
		{Hash: subject.TxID(), Duplicate: &duplicate},
	}}}
	beef := NewBeefV2()
	beef.BUMPs = []*MerklePath{proof}
	beef.Transactions[*parent.TxID()] = &BeefTx{DataFormat: RawTx, Transaction: parent}
	beef.Transactions[*subject.TxID()] = &BeefTx{
		DataFormat:  RawTxAndBumpIndex,
		Transaction: subject,
		BumpIndex:   0,
	}

	atomic, err := beef.AtomicBytes(subject.TxID())
	require.NoError(t, err)
	parsed, target, err := NewBeefFromAtomicBytes(atomic)
	require.NoError(t, err)
	require.Equal(t, subject.TxID(), target)
	require.Contains(t, parsed.Transactions, *parent.TxID(), "a duplicate leaf does not serialize its hash and cannot prove the subject")
	require.Len(t, parsed.BUMPs, 1)
	leaf := parsed.BUMPs[0].Path[0][0]
	require.NotNil(t, leaf.Duplicate)
	require.True(t, *leaf.Duplicate)
	require.Nil(t, leaf.Hash, "duplicate leaf hashes are omitted from BUMP wire bytes")
}

func TestBEEFCompatibilityFixtureUsesPermissiveVarInts(t *testing.T) {
	var buffer bytes.Buffer
	buffer.Write(binary.LittleEndian.AppendUint32(nil, BEEF_V2))
	buffer.Write([]byte{0xfd, 0x00, 0x00}) // zero BUMPs encoded non-canonically
	buffer.Write([]byte{0xfd, 0x00, 0x00}) // zero transactions encoded non-canonically
	parsed, err := NewBeefFromBytes(buffer.Bytes())
	require.NoError(t, err)
	encoded, err := parsed.Bytes()
	require.NoError(t, err)
	require.Equal(t, append(binary.LittleEndian.AppendUint32(nil, BEEF_V2), util.VarInt(0).Bytes()...), encoded[:5])
}

func TestFromBEEFEmptyPreservesReceiver(t *testing.T) {
	tx := benchTx(10)
	before := tx.Bytes()
	err := tx.FromBEEF([]byte{1, 0, 0xbe, 0xef, 0, 0})
	require.ErrorContains(t, err, "no raw transaction")
	require.Equal(t, before, tx.Bytes())
}
