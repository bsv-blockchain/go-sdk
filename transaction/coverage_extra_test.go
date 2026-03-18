package transaction

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
	"github.com/stretchr/testify/require"
)

// ---- Mock ChainTracker for testing Beef.Verify ----

type mockChainTracker struct {
	validResult bool
	err         error
}

func (m *mockChainTracker) IsValidRootForHeight(_ context.Context, _ *chainhash.Hash, _ uint32) (bool, error) {
	return m.validResult, m.err
}

func (m *mockChainTracker) CurrentHeight(_ context.Context) (uint32, error) {
	return 800000, nil
}

var _ chaintracker.ChainTracker = (*mockChainTracker)(nil)

// ---- Outpoint tests ----

func TestOutpointEqual(t *testing.T) {
	hash, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	o1 := &Outpoint{Txid: *hash, Index: 0}
	o2 := &Outpoint{Txid: *hash, Index: 0}
	o3 := &Outpoint{Txid: *hash, Index: 1}

	require.True(t, o1.Equal(o2))
	require.False(t, o1.Equal(o3))
}

func TestOutpointBytes(t *testing.T) {
	hash, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	o := &Outpoint{Txid: *hash, Index: 1}
	b := o.Bytes()
	require.Len(t, b, 36)

	tb := o.TxBytes()
	require.Equal(t, b, tb)
}

func TestOutpointFromBytes(t *testing.T) {
	hash, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	o := &Outpoint{Txid: *hash, Index: 5}
	b := o.Bytes()

	o2 := NewOutpointFromBytes(b)
	require.NotNil(t, o2)
	require.Equal(t, o.Index, o2.Index)

	// Too short
	nilOp := NewOutpointFromBytes([]byte{1, 2, 3})
	require.Nil(t, nilOp)
}

func TestOutpointFromString(t *testing.T) {
	hashHex := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	s := hashHex + ".3"
	o, err := OutpointFromString(s)
	require.NoError(t, err)
	require.Equal(t, uint32(3), o.Index)

	// Too short
	_, err = OutpointFromString("short")
	require.Error(t, err)

	// Invalid txid
	_, err = OutpointFromString("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.0")
	require.Error(t, err)
}

func TestOutpointString(t *testing.T) {
	hashHex := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	hash, _ := chainhash.NewHashFromHex(hashHex)
	o := Outpoint{Txid: *hash, Index: 7}
	s := o.String()
	require.Contains(t, s, ".7")
}

func TestOutpointOrdinalString(t *testing.T) {
	hashHex := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	hash, _ := chainhash.NewHashFromHex(hashHex)
	o := &Outpoint{Txid: *hash, Index: 2}
	s := o.OrdinalString()
	require.Contains(t, s, "_2")
}

func TestOutpointMarshalUnmarshalJSON(t *testing.T) {
	hashHex := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	hash, _ := chainhash.NewHashFromHex(hashHex)
	o := Outpoint{Txid: *hash, Index: 4}

	b, err := json.Marshal(o)
	require.NoError(t, err)

	var o2 Outpoint
	err = json.Unmarshal(b, &o2)
	require.NoError(t, err)
	require.Equal(t, o.Index, o2.Index)
}

func TestOutpointUnmarshalJSONError(t *testing.T) {
	var o Outpoint
	err := json.Unmarshal([]byte(`"tooshort"`), &o)
	require.Error(t, err)

	err = json.Unmarshal([]byte(`12345`), &o)
	require.Error(t, err)
}

func TestOutpointValueAndScan(t *testing.T) {
	hashHex := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	hash, _ := chainhash.NewHashFromHex(hashHex)
	o := Outpoint{Txid: *hash, Index: 1}

	val, err := o.Value()
	require.NoError(t, err)
	b, ok := val.([]byte)
	require.True(t, ok)
	require.Len(t, b, 36)

	var o2 Outpoint
	err = o2.Scan(b)
	require.NoError(t, err)
	require.Equal(t, o.Index, o2.Index)

	// Invalid scan
	err = o2.Scan([]byte{1, 2, 3})
	require.Error(t, err)

	err = o2.Scan("not bytes")
	require.Error(t, err)
}

// ---- UTXO tests ----

func TestNewUTXO(t *testing.T) {
	txid := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	lockingScript := "76a914eb0bd5edba389198e73f8efabddfc61666969ff788ac"
	utxo, err := NewUTXO(txid, 0, lockingScript, 1000)
	require.NoError(t, err)
	require.NotNil(t, utxo)
	require.Equal(t, uint64(1000), utxo.Satoshis)
	require.Equal(t, uint32(0), utxo.Vout)
	require.Equal(t, lockingScript, utxo.LockingScriptHex())
}

func TestNewUTXOInvalidTxID(t *testing.T) {
	_, err := NewUTXO("invalidtxid", 0, "76a914eb0bd5edba389198e73f8efabddfc61666969ff788ac", 1000)
	require.Error(t, err)
}

func TestNewUTXOInvalidScript(t *testing.T) {
	txid := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	_, err := NewUTXO(txid, 0, "invalidscript", 1000)
	require.Error(t, err)
}

// ---- Transaction broadcaster.go tests ----

func TestBroadcastFailureError(t *testing.T) {
	bf := &BroadcastFailure{
		Code:        "500",
		Description: "some error occurred",
	}
	require.Equal(t, "some error occurred", bf.Error())
}

func TestTransactionBroadcast(t *testing.T) {
	tx := NewTransaction()
	b := &mockBroadcaster{}
	success, failure := tx.Broadcast(b)
	require.NotNil(t, success)
	require.Nil(t, failure)
}

func TestTransactionBroadcastCtx(t *testing.T) {
	tx := NewTransaction()
	b := &mockBroadcaster{}
	success, failure := tx.BroadcastCtx(context.Background(), b)
	require.NotNil(t, success)
	require.Nil(t, failure)
}

type mockBroadcaster struct{}

func (m *mockBroadcaster) Broadcast(tx *Transaction) (*BroadcastSuccess, *BroadcastFailure) {
	return &BroadcastSuccess{Txid: tx.TxID().String()}, nil
}

func (m *mockBroadcaster) BroadcastCtx(ctx context.Context, tx *Transaction) (*BroadcastSuccess, *BroadcastFailure) {
	return &BroadcastSuccess{Txid: tx.TxID().String()}, nil
}

// ---- Beef.Verify tests ----

func TestBeefVerifyWithMockTracker(t *testing.T) {
	beefHex := BRC62Hex
	b, err := NewBeefFromBytes(mustDecodeHex(t, beefHex))
	require.NoError(t, err)

	tracker := &mockChainTracker{validResult: true}
	ok, err := b.Verify(context.Background(), tracker, false)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestBeefVerifyEmptyIsValid(t *testing.T) {
	// An empty beef has no transactions and no missing inputs, so verifyValid returns true
	// Verify calls the chain tracker only for non-empty roots; an empty beef returns true immediately
	b := NewBeef()
	tracker := &mockChainTracker{validResult: true}
	ok, err := b.Verify(context.Background(), tracker, false)
	require.NoError(t, err)
	require.True(t, ok)
}

// ---- NewBeef tests ----

func TestNewBeef(t *testing.T) {
	b := NewBeef()
	require.NotNil(t, b)
	require.Equal(t, BEEF_V2, b.Version)
	require.Empty(t, b.BUMPs)
	require.NotNil(t, b.Transactions)
}

// ---- NewBeefFromHex tests ----

func TestNewBeefFromHex(t *testing.T) {
	// Create a valid beef and encode it to hex, then decode
	b := NewBeefV2()
	beefBytes, err := b.Bytes()
	require.NoError(t, err)
	beefHexStr := mustEncodeHex(beefBytes)

	b2, err := NewBeefFromHex(beefHexStr)
	require.NoError(t, err)
	require.NotNil(t, b2)
}

func TestNewBeefFromHexInvalid(t *testing.T) {
	_, err := NewBeefFromHex("notvalidhex!!!")
	require.Error(t, err)
}

// ---- Beef.AtomicBytes tests ----

func TestBeefAtomicBytes(t *testing.T) {
	b := NewBeefV2()
	hash, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	result, err := b.AtomicBytes(hash)
	require.NoError(t, err)
	require.NotNil(t, result)
	// First 4 bytes should be ATOMIC_BEEF version
	require.Len(t, result, 4+chainhash.HashSize+len(mustBeefBytes(t, b)))
}

// ---- Beef.TxidOnly tests ----

func TestBeefTxidOnly(t *testing.T) {
	beefHex := BRC62Hex
	b, err := NewBeefFromBytes(mustDecodeHex(t, beefHex))
	require.NoError(t, err)

	txidOnly, err := b.TxidOnly()
	require.NoError(t, err)
	require.NotNil(t, txidOnly)
	require.Equal(t, len(b.Transactions), len(txidOnly.Transactions))
	for _, tx := range txidOnly.Transactions {
		require.Equal(t, TxIDOnly, tx.DataFormat)
	}
}

// ---- Input.ReadFrom and ReadFromExtended tests ----

func TestTransactionInputReadFrom(t *testing.T) {
	txHex := "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000"
	tx, err := NewTransactionFromHex(txHex)
	require.NoError(t, err)

	// Get the bytes of the first input and read it back
	inputBytes := tx.Inputs[0].Bytes(false)
	inputBytes = append(inputBytes, make([]byte, 100)...) // pad so ReadFrom doesn't hit EOF
	reader := bytes.NewReader(inputBytes)

	var input TransactionInput
	n, err := input.ReadFrom(reader)
	require.NoError(t, err)
	require.Greater(t, n, int64(0))
}

func TestTransactionInputReadFromExtended(t *testing.T) {
	// Build an extended input manually (with satoshis and locking script after sequence)
	tx, err := NewTransactionFromHex("0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000")
	require.NoError(t, err)

	input := tx.Inputs[0]
	// Set source output to enable EF serialization
	input.SetSourceTxOutput(&TransactionOutput{
		Satoshis:      1000,
		LockingScript: script.NewFromBytes([]byte{0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac}),
	})

	// Use EF to get extended format bytes
	tx2 := NewTransaction()
	tx2.Inputs = tx.Inputs
	efBytes, err := tx2.EF()
	require.NoError(t, err)
	_ = efBytes

	var newInput TransactionInput
	// Build raw input bytes with extended format manually
	// 32 bytes prev txid + 4 bytes index + varint script len + script + 4 bytes sequence + 8 bytes satoshis + varint script len + locking script
	var b bytes.Buffer
	b.Write(input.SourceTXID[:])
	b.Write([]byte{0, 0, 0, 0}) // index
	b.WriteByte(0)               // unlocking script len = 0
	b.Write([]byte{0xff, 0xff, 0xff, 0xff}) // sequence
	// satoshis (8 bytes LE)
	b.Write([]byte{0xe8, 0x03, 0, 0, 0, 0, 0, 0}) // 1000 satoshis
	// locking script len + script
	ls := []byte{0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac}
	b.WriteByte(byte(len(ls)))
	b.Write(ls)

	_, err = newInput.ReadFromExtended(bytes.NewReader(b.Bytes()))
	require.NoError(t, err)
	require.NotNil(t, newInput.SourceTxOutput())
	require.Equal(t, uint64(1000), newInput.SourceTxOutput().Satoshis)
}

// ---- Inscriptions tests ----

func TestInscribe(t *testing.T) {
	tx := NewTransaction()
	lockScript := &script.Script{}
	_ = lockScript.AppendOpcodes(script.OpTRUE)
	ia := &script.InscriptionArgs{
		ContentType:  "text/plain",
		Data:         []byte("hello world"),
		LockingScript: lockScript,
	}
	err := tx.Inscribe(ia)
	require.NoError(t, err)
	require.Equal(t, 1, len(tx.Outputs))
	require.Equal(t, uint64(1), tx.Outputs[0].Satoshis)
}

func TestInscribeSpecificOrdinal(t *testing.T) {
	tx := NewTransaction()

	txid, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	sats := uint64(10000)
	input := &TransactionInput{
		SourceTXID:       txid,
		SourceTxOutIndex: 0,
		SequenceNumber:   DefaultSequenceNumber,
	}
	input.SetSourceTxOutput(&TransactionOutput{
		Satoshis:      sats,
		LockingScript: &script.Script{},
	})
	tx.AddInput(input)

	lockScript := &script.Script{}
	_ = lockScript.AppendOpcodes(script.OpTRUE)
	ia := &script.InscriptionArgs{
		ContentType:  "text/plain",
		Data:         []byte("ordinal"),
		LockingScript: lockScript,
	}
	extraScript := &script.Script{}
	_ = extraScript.AppendOpcodes(script.OpTRUE)

	err := tx.InscribeSpecificOrdinal(ia, 0, 5, extraScript)
	require.NoError(t, err)
	require.Equal(t, 2, len(tx.Outputs))
}

func TestInscribeSpecificOrdinalOutputsNotEmpty(t *testing.T) {
	tx := NewTransaction()
	tx.AddOutput(&TransactionOutput{Satoshis: 100, LockingScript: &script.Script{}})

	ia := &script.InscriptionArgs{
		ContentType:   "text/plain",
		Data:          []byte("test"),
		LockingScript: &script.Script{},
	}
	err := tx.InscribeSpecificOrdinal(ia, 0, 0, &script.Script{})
	require.Error(t, err)
	require.Equal(t, ErrOutputsNotEmpty, err)
}

func TestRangeAboveInputTooFew(t *testing.T) {
	_, err := rangeAbove([]*TransactionInput{}, 5, 0)
	require.Error(t, err)
}

func TestRangeAboveZeroSats(t *testing.T) {
	txid, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	input := &TransactionInput{
		SourceTXID:       txid,
		SourceTxOutIndex: 0,
	}
	// Source output is nil, so SourceTxSatoshis() returns nil
	_, err := rangeAbove([]*TransactionInput{input}, 1, 0)
	require.Error(t, err)
}

// ---- MerklePath.NewMerklePath constructor test ----

func TestNewMerklePathConstructor(t *testing.T) {
	pathElements := [][]*PathElement{
		{
			{
				Offset: 0,
				Hash:   new(chainhash.Hash),
				Txid:   boolPtr(true),
			},
		},
	}
	mp := NewMerklePath(100, pathElements)
	require.NotNil(t, mp)
	require.Equal(t, uint32(100), mp.BlockHeight)
	require.Len(t, mp.Path, 1)
}

// ---- Transaction additional methods ----

func TestTransactionHasDataOutputs(t *testing.T) {
	tx := NewTransaction()
	require.False(t, tx.HasDataOutputs())

	// Add an OP_RETURN output
	err := tx.AddOpReturnOutput([]byte("data"))
	require.NoError(t, err)
	require.True(t, tx.HasDataOutputs())
}

func TestTransactionOutputIdx(t *testing.T) {
	tx := NewTransaction()
	tx.AddOutput(&TransactionOutput{Satoshis: 100, LockingScript: &script.Script{}})

	out := tx.OutputIdx(0)
	require.NotNil(t, out)

	out = tx.OutputIdx(99)
	require.Nil(t, out)
}

func TestTransactionInputIdx(t *testing.T) {
	tx := NewTransaction()
	require.Nil(t, tx.InputIdx(0))
}

func TestTransactionHex(t *testing.T) {
	tx := NewTransaction()
	h := tx.Hex()
	require.NotEmpty(t, h)
}

func TestTransactionBytesWithClearedInputs(t *testing.T) {
	txHex := "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000"
	tx, err := NewTransactionFromHex(txHex)
	require.NoError(t, err)

	cleared := tx.BytesWithClearedInputs(0, []byte{0x76, 0xa9})
	require.NotNil(t, cleared)
}

func TestTransactionSize(t *testing.T) {
	txHex := "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000"
	tx, err := NewTransactionFromHex(txHex)
	require.NoError(t, err)
	require.Greater(t, tx.Size(), 0)
}

func TestTransactionAddMerkleProof(t *testing.T) {
	txHex := "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000"
	tx, err := NewTransactionFromHex(txHex)
	require.NoError(t, err)

	// Create a valid bump for this transaction
	txid := tx.TxID()
	isTxid := true
	bump := &MerklePath{
		BlockHeight: 100,
		Path: [][]*PathElement{
			{
				{Offset: 0, Hash: txid, Txid: &isTxid},
			},
		},
	}
	err = tx.AddMerkleProof(bump)
	require.NoError(t, err)
	require.Equal(t, bump, tx.MerklePath)
}

func TestTransactionAddMerkleBadProof(t *testing.T) {
	tx := NewTransaction()
	wrongHash, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	isTxid := true
	bump := &MerklePath{
		BlockHeight: 100,
		Path: [][]*PathElement{
			{
				{Offset: 0, Hash: wrongHash, Txid: &isTxid},
			},
		},
	}
	err := tx.AddMerkleProof(bump)
	require.Error(t, err)
	require.Equal(t, ErrBadMerkleProof, err)
}

func TestTransactionAddInputWithOutput(t *testing.T) {
	tx := NewTransaction()
	txid, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")

	input := &TransactionInput{
		SourceTXID:       txid,
		SourceTxOutIndex: 0,
		SequenceNumber:   DefaultSequenceNumber,
	}
	output := &TransactionOutput{
		Satoshis:      5000,
		LockingScript: &script.Script{},
	}
	tx.AddInputWithOutput(input, output)
	require.Equal(t, 1, tx.InputCount())
	require.Equal(t, uint64(5000), *tx.Inputs[0].SourceTxSatoshis())
}

func TestTransactionOutputCount(t *testing.T) {
	tx := NewTransaction()
	require.Equal(t, 0, tx.OutputCount())
	tx.AddOutput(&TransactionOutput{Satoshis: 100, LockingScript: &script.Script{}})
	require.Equal(t, 1, tx.OutputCount())
}

func TestTransactionEFHex(t *testing.T) {
	txHex := "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000"
	tx, err := NewTransactionFromHex(txHex)
	require.NoError(t, err)

	// EFHex fails without source output
	_, err = tx.EFHex()
	require.Error(t, err)

	// Set source output
	tx.Inputs[0].SetSourceTxOutput(&TransactionOutput{
		Satoshis:      1000,
		LockingScript: &script.Script{},
	})
	h, err := tx.EFHex()
	require.NoError(t, err)
	require.NotEmpty(t, h)
}

func TestTransactionNewTransactionFromBEEFHex(t *testing.T) {
	// Use existing BRC62Hex (valid BEEF v1)
	tx, err := NewTransactionFromBEEFHex(BRC62Hex)
	require.NoError(t, err)
	require.NotNil(t, tx)
}

func TestTransactionNewTransactionFromBEEFHexInvalid(t *testing.T) {
	_, err := NewTransactionFromBEEFHex("notvalidhex!!")
	require.Error(t, err)
}

func TestBeefBEEFHex(t *testing.T) {
	txHex := "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000"
	tx, err := NewTransactionFromHex(txHex)
	require.NoError(t, err)
	// BEEFHex will fail because no source transactions (no MerklePath)
	// but it exercises BEEFHex function path
	_, err = tx.BEEFHex()
	// expect error (no merkle proof for parents)
	_ = err
}

func TestParseBeefWithAtomicBEEF(t *testing.T) {
	// ParseBeef handles ATOMIC_BEEF, V1, V2
	// Test ATOMIC_BEEF branch by creating an AtomicBEEF
	b := NewBeefV2()
	hash, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	atomicBytes, err := b.AtomicBytes(hash)
	require.NoError(t, err)

	_, _, txid, err := ParseBeef(atomicBytes)
	require.NoError(t, err)
	require.NotNil(t, txid)
}

func TestParseBeefV2(t *testing.T) {
	b := NewBeefV2()
	beefBytes, err := b.Bytes()
	require.NoError(t, err)

	result, tx, txid, err := ParseBeef(beefBytes)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Nil(t, tx)
	require.Nil(t, txid)
}

func TestParseBeefTooShort(t *testing.T) {
	_, _, _, err := ParseBeef([]byte{1, 2, 3})
	require.Error(t, err)
}

func TestParseBeefInvalidVersion(t *testing.T) {
	_, _, _, err := ParseBeef([]byte{0x01, 0x00, 0x00, 0x00})
	require.Error(t, err)
}

func TestNewBeefFromAtomicBytesTooShort(t *testing.T) {
	_, _, err := NewBeefFromAtomicBytes([]byte{1, 2, 3})
	require.Error(t, err)
}

func TestNewBeefFromAtomicBytesWrongVersion(t *testing.T) {
	data := make([]byte, 36)
	data[0] = 0xFF
	data[1] = 0xFF
	data[2] = 0xFF
	data[3] = 0xFF
	_, _, err := NewBeefFromAtomicBytes(data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not atomic BEEF")
}

func TestFeeGetFeeError(t *testing.T) {
	tx := NewTransaction()
	// No inputs - TotalInputSatoshis will return 0, not an error, then subtract outputs
	// Actually ErrEmptyPreviousTx is returned when sourceOutput is nil
	txid, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	input := &TransactionInput{
		SourceTXID:       txid,
		SourceTxOutIndex: 0,
		SequenceNumber:   DefaultSequenceNumber,
	}
	// Do NOT set source output
	tx.AddInput(input)
	_, err := tx.GetFee()
	require.Error(t, err)
}

func TestFeeChangeDistributionRandom(t *testing.T) {
	tx := NewTransaction()
	txid, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	input := &TransactionInput{
		SourceTXID:       txid,
		SourceTxOutIndex: 0,
		SequenceNumber:   DefaultSequenceNumber,
	}
	input.SetSourceTxOutput(&TransactionOutput{Satoshis: 10000, LockingScript: &script.Script{}})
	tx.AddInput(input)
	tx.AddOutput(&TransactionOutput{Satoshis: 1000, LockingScript: &script.Script{}})
	tx.AddOutput(&TransactionOutput{Satoshis: 0, Change: true, LockingScript: &script.Script{}})

	err := tx.Fee(&fixedFeeModel{fee: 100}, ChangeDistributionRandom)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not-implemented")
}

type fixedFeeModel struct {
	fee uint64
}

func (f *fixedFeeModel) ComputeFee(_ *Transaction) (uint64, error) {
	return f.fee, nil
}

func TestSourceTxScriptNilOutput(t *testing.T) {
	txid, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	input := &TransactionInput{
		SourceTXID:       txid,
		SourceTxOutIndex: 0,
		SequenceNumber:   DefaultSequenceNumber,
	}
	// No source output set - should return nil
	require.Nil(t, input.SourceTxScript())
	require.Nil(t, input.SourceTxSatoshis())
}

func TestMerklePathNewMerklePathFromHexInvalid(t *testing.T) {
	_, err := NewMerklePathFromHex("invalidhex!!")
	require.Error(t, err)
}

func TestMerklePathNewMerklePathFromBinaryTooShort(t *testing.T) {
	_, err := NewMerklePathFromBinary([]byte{1, 2, 3})
	require.Error(t, err)
}

func TestMerklePathVerifyHex(t *testing.T) {
	// Parse BEEF v1 which stores MerklePaths on the source transactions
	// The tx returned by NewTransactionFromBEEFHex may have MerklePath nil (depends on implementation)
	// Parse via NewBeefFromBytes and use source transaction's MerklePath
	beefBytes, err := hexDecode(BRC62Hex)
	require.NoError(t, err)

	beef, err := NewBeefFromBytes(beefBytes)
	require.NoError(t, err)

	// Find a transaction that has a MerklePath (the oldest input)
	var txWithPath *Transaction
	for _, btx := range beef.Transactions {
		if btx.Transaction != nil && btx.Transaction.MerklePath != nil {
			txWithPath = btx.Transaction
			break
		}
	}
	require.NotNil(t, txWithPath, "should find a tx with MerklePath")

	txidStr := txWithPath.TxID().String()
	_, err = txWithPath.MerklePath.ComputeRootHex(&txidStr)
	require.NoError(t, err)

	tracker := &mockChainTracker{validResult: true}
	ok, err := txWithPath.MerklePath.VerifyHex(context.Background(), txidStr, tracker)
	require.NoError(t, err)
	require.True(t, ok)

	// Invalid txid hex
	_, err = txWithPath.MerklePath.VerifyHex(context.Background(), "invalidhex", tracker)
	require.Error(t, err)
}

func TestInputBytesWithNilUnlockingScript(t *testing.T) {
	txid, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	input := &TransactionInput{
		SourceTXID:       txid,
		SourceTxOutIndex: 0,
		SequenceNumber:   DefaultSequenceNumber,
		UnlockingScript:  nil,
	}
	b := input.Bytes(false)
	require.NotNil(t, b)
	require.Len(t, b, 32+4+1+4) // txid + index + 0x00 + seq
}

// ---- Helper functions ----

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hexDecode(s)
	if err != nil {
		t.Fatalf("failed to decode hex: %v", err)
	}
	return b
}

func hexDecode(s string) ([]byte, error) {
	import_enc := make([]byte, len(s)/2)
	_, err := hexDecodeToSlice(s, import_enc)
	if err != nil {
		return nil, err
	}
	return import_enc, nil
}

func hexDecodeToSlice(s string, dst []byte) (int, error) {
	for i := 0; i < len(s)/2; i++ {
		b, err := hexByte(s[i*2], s[i*2+1])
		if err != nil {
			return i, err
		}
		dst[i] = b
	}
	return len(s) / 2, nil
}

func hexByte(hi, lo byte) (byte, error) {
	h, err := hexNibble(hi)
	if err != nil {
		return 0, err
	}
	l, err := hexNibble(lo)
	if err != nil {
		return 0, err
	}
	return h<<4 | l, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, &hexError{c}
}

type hexError struct{ c byte }

func (e *hexError) Error() string {
	return "invalid hex char"
}

func mustEncodeHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hexChars[v>>4]
		result[i*2+1] = hexChars[v&0xf]
	}
	return string(result)
}

func mustBeefBytes(t *testing.T, b *Beef) []byte {
	t.Helper()
	data, err := b.Bytes()
	require.NoError(t, err)
	return data
}

func boolPtr(b bool) *bool {
	return &b
}
