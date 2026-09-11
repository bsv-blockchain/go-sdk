package transaction

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
)

func le32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// simpleFundedChild builds a child transaction that spends a parent output, so
// NewBeefFromTransaction has an ancestry to walk.
func simpleFundedChild(t *testing.T) *Transaction {
	t.Helper()
	src := NewTransaction()
	src.AddOutput(&TransactionOutput{Satoshis: 1000, LockingScript: &script.Script{}})
	child := NewTransaction()
	child.AddInputFromTx(src, 0, nil)
	child.AddOutput(&TransactionOutput{Satoshis: 900, LockingScript: &script.Script{}})
	return child
}

func TestBeefBumpRootError(t *testing.T) {
	t.Parallel()
	b := NewBeef()
	_, err := b.bumpRoot(brokenTwoLevelPath(1, mpHashA(t)))
	require.Error(t, err)
}

func TestBeefBumpProvesGuards(t *testing.T) {
	t.Parallel()
	b := NewBeef()
	assert.False(t, b.bumpProves(singleLeafPath(1, mpHashA(t)), nil))
	assert.False(t, b.bumpProves(&MerklePath{BlockHeight: 1}, mpHashA(t)))
}

func TestNewBeefFromBytesErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data []byte
	}{
		{name: "atomic-too-short", data: append(le32(ATOMIC_BEEF), make([]byte, 10)...)},
		{name: "bad-version-read", data: []byte{0x00, 0x00}},
		{name: "v1-bumps-eof", data: le32(BEEF_V1)},
		{name: "v1-transactions-eof", data: append(le32(BEEF_V1), 0x00)},
		{name: "v2-bumps-eof", data: le32(BEEF_V2)},
		{name: "bumps-count-overflow", data: append(le32(BEEF_V2), 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)},
		{name: "bump-parse-error", data: append(le32(BEEF_V2), 0x01, 0x00, 0x01)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewBeefFromBytes(tc.data)
			require.Error(t, err)
		})
	}
}

func TestNewBeefFromBytesAtomicRoundTrip(t *testing.T) {
	t.Parallel()
	child := simpleFundedChild(t)
	b, err := NewBeefFromTransaction(child)
	require.NoError(t, err)

	atomic, err := b.AtomicBytes(child.TxID())
	require.NoError(t, err)

	parsed, err := NewBeefFromBytes(atomic)
	require.NoError(t, err)
	require.NotNil(t, parsed.FindTransaction(child.TxID().String()))
}

func TestNewBeefFromAtomicBytesBodyInvalid(t *testing.T) {
	t.Parallel()
	data := append(le32(ATOMIC_BEEF), make([]byte, 32)...)
	data = append(data, 0x00, 0x00) // body too short for readVersion
	_, _, err := NewBeefFromAtomicBytes(data)
	require.Error(t, err)
}

func TestParseBeefErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data []byte
	}{
		{name: "atomic-too-short", data: append(le32(ATOMIC_BEEF), make([]byte, 10)...)},
		{name: "atomic-body-invalid", data: append(append(le32(ATOMIC_BEEF), make([]byte, 32)...), 0x00, 0x00)},
		{name: "v1-transaction-invalid", data: le32(BEEF_V1)},
		{name: "v2-invalid", data: le32(BEEF_V2)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, _, err := ParseBeef(tc.data)
			require.Error(t, err)
		})
	}
}

func TestNewBeefFromTransactionErrors(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		_, err := NewBeefFromTransaction(nil)
		require.Error(t, err)
	})

	t.Run("missing-ancestor", func(t *testing.T) {
		t.Parallel()
		tx := NewTransaction()
		tx.AddInput(&TransactionInput{SourceTXID: &chainhash.Hash{}, SequenceNumber: DefaultSequenceNumber})
		tx.AddOutput(&TransactionOutput{Satoshis: 1, LockingScript: &script.Script{}})
		_, err := NewBeefFromTransaction(tx)
		require.Error(t, err)
	})
}

func TestCollectAncestorsGrandparentMissing(t *testing.T) {
	t.Parallel()
	// b spends a missing grandparent; a spends b. Collecting a's ancestry must
	// surface the recursive failure.
	b := NewTransaction()
	b.AddInput(&TransactionInput{SourceTXID: &chainhash.Hash{}, SequenceNumber: DefaultSequenceNumber})
	b.AddOutput(&TransactionOutput{Satoshis: 500, LockingScript: &script.Script{}})

	a := NewTransaction()
	a.AddInputFromTx(b, 0, nil)
	a.AddOutput(&TransactionOutput{Satoshis: 400, LockingScript: &script.Script{}})

	_, err := NewBeefFromTransaction(a)
	require.Error(t, err)
}

func TestReadBUMPsAndTransactionsErrors(t *testing.T) {
	t.Parallel()
	// Valid empty-BUMP prefix, then malformed transaction section.
	tests := []struct {
		name string
		data []byte
	}{
		{name: "tx-read-error", data: buildV1(0x00, []byte{0x01, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})},
		{name: "hasbump-eof", data: buildV1(0x00, append([]byte{0x01}, minimalTxBytes()...))},
		{name: "pathindex-eof", data: buildV1(0x00, append(append([]byte{0x01}, minimalTxBytes()...), 0x01))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewBeefFromBytes(tc.data)
			require.Error(t, err)
		})
	}
}

// buildV1 assembles a BEEF v1 byte stream: version, a bump count byte, and a raw
// transaction section.
func buildV1(bumpCount byte, txSection []byte) []byte {
	out := le32(BEEF_V1)
	out = append(out, bumpCount)
	return append(out, txSection...)
}

func minimalTxBytes() []byte {
	tx := NewTransaction()
	return tx.Bytes()
}

func TestBeefFindHelpersInvalidInput(t *testing.T) {
	t.Parallel()
	b := NewBeef()
	assert.Nil(t, b.FindBumpByHash(nil))
	assert.Nil(t, b.FindBump("zz"))
	assert.Nil(t, b.FindTransaction("zz"))
	assert.Nil(t, b.FindTransactionForSigning("zz"))
	assert.Nil(t, b.FindTransactionForSigningByHash(mpHashA(t)))
	assert.Nil(t, b.FindAtomicTransaction("zz"))
	assert.Nil(t, b.FindAtomicTransactionByHash(mpHashA(t)))
}

func TestFindTransactionForSigningLinksSource(t *testing.T) {
	t.Parallel()
	src := NewTransaction()
	src.AddOutput(&TransactionOutput{Satoshis: 1000, LockingScript: &script.Script{}})
	child := NewTransaction()
	child.AddInput(&TransactionInput{SourceTXID: src.TxID(), SourceTxOutIndex: 0, SequenceNumber: DefaultSequenceNumber})
	child.AddOutput(&TransactionOutput{Satoshis: 900, LockingScript: &script.Script{}})

	b := NewBeef()
	b.Transactions[*src.TxID()] = &BeefTx{DataFormat: RawTx, Transaction: src}
	b.Transactions[*child.TxID()] = &BeefTx{DataFormat: RawTx, Transaction: child}

	got := b.FindTransactionForSigningByHash(child.TxID())
	require.NotNil(t, got)
	require.NotNil(t, child.Inputs[0].SourceTransaction)
}

func TestFindAtomicTransactionLinksSources(t *testing.T) {
	t.Parallel()
	src := NewTransaction()
	src.AddOutput(&TransactionOutput{Satoshis: 1000, LockingScript: &script.Script{}})

	missing := mpHashB(t)
	child := NewTransaction()
	child.AddInput(&TransactionInput{SourceTXID: src.TxID(), SourceTxOutIndex: 0, SequenceNumber: DefaultSequenceNumber})
	child.AddInput(&TransactionInput{SourceTXID: missing, SourceTxOutIndex: 0, SequenceNumber: DefaultSequenceNumber})
	child.AddOutput(&TransactionOutput{Satoshis: 900, LockingScript: &script.Script{}})

	b := NewBeef()
	b.Transactions[*src.TxID()] = &BeefTx{DataFormat: RawTx, Transaction: src}
	b.Transactions[*child.TxID()] = &BeefTx{DataFormat: RawTx, Transaction: child}

	got := b.FindAtomicTransactionByHash(child.TxID())
	require.NotNil(t, got)
	require.NotNil(t, child.Inputs[0].SourceTransaction)
}

func TestMergeBumpBranches(t *testing.T) {
	t.Parallel()
	a := mpHashA(t)
	b := mpHashB(t)

	t.Run("same-pointer", func(t *testing.T) {
		t.Parallel()
		bf := NewBeef()
		bump := singleLeafPath(5, a)
		first := bf.MergeBump(bump)
		second := bf.MergeBump(bump)
		assert.Equal(t, first, second)
	})

	t.Run("incoming-root-error", func(t *testing.T) {
		t.Parallel()
		bf := NewBeef()
		bf.MergeBump(singleLeafPath(5, a))
		assert.Equal(t, -1, bf.MergeBump(brokenTwoLevelPath(5, a)))
	})

	t.Run("existing-root-error", func(t *testing.T) {
		t.Parallel()
		bf := NewBeef()
		bf.MergeBump(brokenTwoLevelPath(5, a))
		assert.Equal(t, -1, bf.MergeBump(singleLeafPath(5, b)))
	})
}

func TestMakeTxidOnlyBranches(t *testing.T) {
	t.Parallel()
	assert.Nil(t, NewBeef().MakeTxidOnly(nil))
	assert.Nil(t, NewBeef().MakeTxidOnly(mpHashA(t)))

	child := simpleFundedChild(t)
	b, err := NewBeefFromTransaction(child)
	require.NoError(t, err)
	txid := child.TxID()

	first := b.MakeTxidOnly(txid)
	require.NotNil(t, first)
	assert.Equal(t, TxIDOnly, first.DataFormat)
	// Calling again returns the already-converted entry.
	second := b.MakeTxidOnly(txid)
	assert.Equal(t, first, second)
}

func TestMergeRawTxErrors(t *testing.T) {
	t.Parallel()
	b := NewBeef()

	_, err := b.MergeRawTx([]byte{0x01, 0x02}, nil)
	require.Error(t, err)

	badIndex := 99
	_, err = b.MergeRawTx(minimalTxBytes(), &badIndex)
	require.Error(t, err)
}

func TestMergeNilInputs(t *testing.T) {
	t.Parallel()
	b := NewBeef()
	assert.Nil(t, b.MergeTxidOnly(nil))

	_, err := b.MergeBeefTx(nil)
	require.Error(t, err)
	_, err = b.MergeBeefTx(&BeefTx{DataFormat: RawTx})
	require.Error(t, err)
	_, err = b.MergeBeefTxWithTxid(mpHashA(t), nil)
	require.Error(t, err)
}

func TestMergeBeefWithBumps(t *testing.T) {
	t.Parallel()
	other := NewBeef()
	other.MergeBump(singleLeafPath(7, mpHashA(t)))

	b := NewBeef()
	require.NoError(t, b.MergeBeef(other))
	require.Len(t, b.BUMPs, 1)
}

func TestBeefVerifyInvalidGraph(t *testing.T) {
	t.Parallel()
	child := NewTransaction()
	child.AddInput(&TransactionInput{SourceTXID: mpHashA(t), SourceTxOutIndex: 0, SequenceNumber: DefaultSequenceNumber})
	child.AddOutput(&TransactionOutput{Satoshis: 1, LockingScript: &script.Script{}})

	b := NewBeef()
	b.Transactions[*child.TxID()] = &BeefTx{DataFormat: RawTx, Transaction: child}

	ok, err := b.Verify(context.Background(), &mockChainTracker{validResult: true}, false)
	require.NoError(t, err)
	assert.False(t, ok)
}

// provedBeef builds a valid single-transaction BEEF whose transaction is proven
// by a one-leaf merkle path, so verifyValid computes a real root.
func provedBeef(t *testing.T) *Beef {
	t.Helper()
	tx := NewTransaction()
	tx.AddOutput(&TransactionOutput{Satoshis: 1, LockingScript: &script.Script{}})
	txid := tx.TxID()
	truthy := true
	mp := &MerklePath{
		BlockHeight: 800000,
		Path:        [][]*PathElement{{{Offset: 0, Hash: txid, Txid: &truthy}}},
	}
	tx.MerklePath = mp
	b := NewBeef()
	b.BUMPs = []*MerklePath{mp}
	b.Transactions[*txid] = &BeefTx{DataFormat: RawTxAndBumpIndex, Transaction: tx, BumpIndex: 0}
	return b
}

func TestBeefVerifyProvenRootRejected(t *testing.T) {
	t.Parallel()
	b := provedBeef(t)
	ok, err := b.Verify(context.Background(), &mockChainTracker{validResult: false}, false)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestBeefVerifyProvenRootAccepted(t *testing.T) {
	t.Parallel()
	b := provedBeef(t)
	ok, err := b.Verify(context.Background(), &mockChainTracker{validResult: true}, false)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestBeefToLogStringWithProof(t *testing.T) {
	t.Parallel()
	b := provedBeef(t)
	log := b.ToLogString()
	assert.Contains(t, log, "BUMP")
	assert.Contains(t, log, "bumpIndex")
}

func TestValidateTransactionsNotValid(t *testing.T) {
	t.Parallel()
	tx := NewTransaction()
	tx.AddInput(&TransactionInput{SourceTXID: mpHashA(t), SourceTxOutIndex: 0, SequenceNumber: DefaultSequenceNumber})
	tx.AddOutput(&TransactionOutput{Satoshis: 1, LockingScript: &script.Script{}})

	b := NewBeef()
	// Invalid bump index and an input to an unproven txid-only source.
	b.Transactions[*tx.TxID()] = &BeefTx{DataFormat: RawTxAndBumpIndex, Transaction: tx, BumpIndex: 99}
	b.Transactions[*mpHashA(t)] = &BeefTx{DataFormat: TxIDOnly, KnownTxID: mpHashA(t)}

	result := b.ValidateTransactions()
	require.NotNil(t, result)
	assert.NotEmpty(t, result.NotValid)
}

func TestBeefBytesSerializationErrors(t *testing.T) {
	t.Parallel()

	t.Run("txidonly-nil-known", func(t *testing.T) {
		t.Parallel()
		b := NewBeef()
		b.Transactions[chainhash.Hash{}] = &BeefTx{DataFormat: TxIDOnly, KnownTxID: nil}
		_, err := b.Bytes()
		require.Error(t, err)
	})

	t.Run("rawtx-nil-transaction", func(t *testing.T) {
		t.Parallel()
		b := NewBeef()
		b.Transactions[chainhash.Hash{}] = &BeefTx{DataFormat: RawTx, Transaction: nil}
		_, err := b.Bytes()
		require.Error(t, err)
	})
}

func TestBeefTxidOnlyConversion(t *testing.T) {
	t.Parallel()
	child := simpleFundedChild(t)
	b, err := NewBeefFromTransaction(child)
	require.NoError(t, err)
	// Add an explicit TxIDOnly entry too.
	b.Transactions[*mpHashA(t)] = &BeefTx{DataFormat: TxIDOnly, KnownTxID: mpHashA(t)}

	c, err := b.TxidOnly()
	require.NoError(t, err)
	for _, tx := range c.Transactions {
		assert.Equal(t, TxIDOnly, tx.DataFormat)
		require.NotNil(t, tx.KnownTxID)
	}
}

func TestMergeWouldNotChange(t *testing.T) {
	t.Parallel()
	b := NewBeef()
	existing := &BeefTx{DataFormat: RawTx, Transaction: NewTransaction()}

	// Input carrying a source transaction but no SourceTXID to reason about.
	nilSourceID := NewTransaction()
	nilSourceID.AddInput(&TransactionInput{SourceTransaction: NewTransaction(), SequenceNumber: DefaultSequenceNumber})
	assert.False(t, b.mergeWouldNotChange(existing, nilSourceID))

	// Input whose source is not present in the beef as a raw transaction.
	unknownSource := NewTransaction()
	unknownSource.AddInput(&TransactionInput{
		SourceTXID:        mpHashA(t),
		SourceTransaction: NewTransaction(),
		SequenceNumber:    DefaultSequenceNumber,
	})
	assert.False(t, b.mergeWouldNotChange(existing, unknownSource))
}

func TestTrimUnreferencedBumpsEmpty(t *testing.T) {
	t.Parallel()
	b := NewBeef()
	// No bumps -> trimming is a no-op early return.
	b.TrimknownTxIDs(nil)
	assert.Empty(t, b.BUMPs)
}

func TestTrimUnreferencedBumpsMixedFormats(t *testing.T) {
	t.Parallel()
	rawTx := NewTransaction()
	rawTx.AddOutput(&TransactionOutput{Satoshis: 1, LockingScript: &script.Script{}})
	rawTxID := rawTx.TxID()
	known := mpHashA(t)
	truthy := true

	bump0 := &MerklePath{BlockHeight: 1, Path: [][]*PathElement{{{Offset: 0, Hash: rawTxID, Txid: &truthy}}}}
	bump1 := &MerklePath{BlockHeight: 2, Path: [][]*PathElement{{{Offset: 0, Hash: known, Txid: &truthy}}}}
	bump2 := &MerklePath{BlockHeight: 3, Path: [][]*PathElement{{{Offset: 0, Hash: mpHashB(t), Txid: &truthy}}}}

	b := NewBeef()
	b.BUMPs = []*MerklePath{bump0, bump1, bump2}
	b.Transactions[*rawTxID] = &BeefTx{DataFormat: RawTx, Transaction: rawTx}
	b.Transactions[*known] = &BeefTx{DataFormat: TxIDOnly, KnownTxID: known}

	// Nothing is deleted (empty known-list), but bump2 is referenced by no
	// remaining transaction and is trimmed.
	b.TrimknownTxIDs(nil)
	assert.Len(t, b.BUMPs, 2)
}

func TestTrimUnreferencedBumps(t *testing.T) {
	t.Parallel()
	tx := NewTransaction()
	tx.AddOutput(&TransactionOutput{Satoshis: 1, LockingScript: &script.Script{}})
	txid := tx.TxID()
	truthy := true

	mp0 := &MerklePath{BlockHeight: 1, Path: [][]*PathElement{{{Offset: 0, Hash: txid, Txid: &truthy}}}}
	known := mpHashB(t)
	mp1 := &MerklePath{BlockHeight: 2, Path: [][]*PathElement{{{Offset: 0, Hash: known, Txid: &truthy}}}}

	b := NewBeef()
	b.BUMPs = []*MerklePath{mp0, mp1}
	b.Transactions[*txid] = &BeefTx{DataFormat: RawTxAndBumpIndex, Transaction: tx, BumpIndex: 0}
	b.Transactions[*known] = &BeefTx{DataFormat: TxIDOnly, KnownTxID: known}

	b.TrimknownTxIDs([]string{known.String()})

	// The txid-only entry and its now-unreferenced bump are trimmed.
	assert.Len(t, b.BUMPs, 1)
	_, stillThere := b.Transactions[*known]
	assert.False(t, stillThere)
}
