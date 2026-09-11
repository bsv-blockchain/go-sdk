package transaction

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"slices"

	"github.com/pkg/errors"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/util"
)

type Transaction struct {
	Version    uint32               `json:"version"`
	Inputs     []*TransactionInput  `json:"inputs"`
	Outputs    []*TransactionOutput `json:"outputs"`
	LockTime   uint32               `json:"locktime"`
	MerklePath *MerklePath          `json:"merklePath"`

	// cachedTxID is an optional, caller-populated txid cache. It is set ONLY via
	// SetTxHash and is never auto-populated by TxID(), so a read can never leave
	// a value that later goes stale on its own; the caller opts in and owns
	// invalidation. Unexported, so it is ignored by JSON and does not affect the
	// public API.
	cachedTxID *chainhash.Hash
}

// Transactions a collection of *transaction.Transaction.
type Transactions []*Transaction

// NewTransaction creates a new transaction object with default values.
func NewTransaction() *Transaction {
	return &Transaction{Version: 1, LockTime: 0, Inputs: make([]*TransactionInput, 0)}
}

// NewTransactionFromHex takes a toBytesHelper string representation of a bitcoin transaction
// and returns a Tx object.
func NewTransactionFromHex(str string) (*Transaction, error) {
	bb, err := hex.DecodeString(str)
	if err != nil {
		return nil, err
	}

	return NewTransactionFromBytes(bb)
}

// NewTransactionFromBytes takes an array of bytes, constructs a Tx and returns it.
// This function assumes that the byte slice contains exactly 1 transaction.
func NewTransactionFromBytes(b []byte) (*Transaction, error) {
	tx, used, err := NewTransactionFromStream(b)
	if err != nil {
		return nil, err
	}

	if used != len(b) {
		return nil, ErrNLockTimeLength
	}

	return tx, nil
}

// NewTransactionFromStream takes an array of bytes and constructs a Tx from it, returning the Tx and the bytes used.
// Despite the name, this is not actually reading a stream in the true sense: it is a byte slice that contains
// many transactions one after another.
func NewTransactionFromStream(b []byte) (*Transaction, int, error) {
	tx := Transaction{}

	bytesRead, err := tx.ReadFrom(bytes.NewReader(b))

	return &tx, int(bytesRead), err
}

// ReadFrom reads from the `io.Reader` into the `transaction.Transaction`.
func (tx *Transaction) ReadFrom(r io.Reader) (int64, error) {
	*tx = Transaction{}
	var bytesRead int64

	// Define n64 and err here to avoid linter complaining about shadowing variables.
	var n64 int64
	var err error

	// One reusable scratch buffer for every fixed-size field and length prefix
	// in this parse: large enough for the 32-byte previous-txid, and threaded
	// into input/output parsing. Slices of it feed binary.LittleEndian and
	// chainhash.NewHash (which read/copy immediately) and readVarInt, so the
	// whole transaction decodes with a single header allocation instead of a
	// fresh make([]byte, ...) per field.
	scratch := make([]byte, 32)

	n, err := io.ReadFull(r, scratch[:4])
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, err
	}

	tx.Version = binary.LittleEndian.Uint32(scratch[:4])

	extended := false

	var inputCount uint64

	inputCount, n64, err = readVarInt(r, scratch)
	bytesRead += n64
	if err != nil {
		return bytesRead, err
	}

	var outputCount uint64

	// ----------------------------------------------------------------------------------
	// If the inputCount is 0, we may be parsing an incomplete transaction, or we may be
	// both of these cases without needing to rewind (peek) the incoming stream of bytes.
	// ----------------------------------------------------------------------------------
	if inputCount == 0 {
		outputCount, n64, err = readVarInt(r, scratch)
		bytesRead += n64
		if err != nil {
			return bytesRead, err
		}

		if outputCount == 0 {
			// Read in lock time
			n, err = io.ReadFull(r, scratch[:4])
			bytesRead += int64(n)
			if err != nil {
				return bytesRead, err
			}

			if binary.BigEndian.Uint32(scratch[:4]) != 0xEF {
				tx.LockTime = binary.LittleEndian.Uint32(scratch[:4])
				return bytesRead, nil
			}

			extended = true

			inputCount, n64, err = readVarInt(r, scratch)
			bytesRead += n64
			if err != nil {
				return bytesRead, err
			}
		}
	}
	// ----------------------------------------------------------------------------------
	// If we have not returned from the previous block, we will have detected a sane
	// transaction and we will know if it is extended format or not.
	// We can now proceed with reading the rest of the transaction.
	// ----------------------------------------------------------------------------------

	// create Inputs
	if _, ok := r.(byteLenReader); ok {
		// In-memory reader (the untrusted-binary parse entry points wrap their
		// input in a *bytes.Reader): pre-size the slice, first guarding the
		// attacker-controlled count against the bytes that remain (min 41 per
		// input) so make() cannot be handed an oversized length. Streaming
		// readers, which cannot report a remaining length, keep appending
		// unchanged.
		if err = guardParseCount(r, inputCount, minInputParseBytes, "inputs"); err != nil {
			return bytesRead, err
		}
		tx.Inputs = make([]*TransactionInput, 0, inputCount)
	}
	for i := uint64(0); i < inputCount; i++ {
		input := &TransactionInput{}
		n64, err = input.readFrom(r, extended, scratch)
		bytesRead += n64
		if err != nil {
			return bytesRead, err
		}
		tx.Inputs = append(tx.Inputs, input)
	}

	if inputCount > 0 || extended {
		// Re-read the actual output count...
		outputCount, n64, err = readVarInt(r, scratch)
		bytesRead += n64
		if err != nil {
			return bytesRead, err
		}
	}

	if _, ok := r.(byteLenReader); ok {
		if err = guardParseCount(r, outputCount, minOutputParseBytes, "outputs"); err != nil {
			return bytesRead, err
		}
		tx.Outputs = make([]*TransactionOutput, 0, outputCount)
	}
	for i := uint64(0); i < outputCount; i++ {
		output := new(TransactionOutput)
		n64, err = output.readFrom(r, scratch)
		bytesRead += n64
		if err != nil {
			return bytesRead, err
		}

		tx.Outputs = append(tx.Outputs, output)
	}

	n, err = io.ReadFull(r, scratch[:4])
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, err
	}
	tx.LockTime = binary.LittleEndian.Uint32(scratch[:4])

	return bytesRead, nil
}

// ReadFrom txs from a block in a `transaction.Transactions`. This assumes a preceding varint detailing
// the total number of txs that the reader will provide.
func (tt *Transactions) ReadFrom(r io.Reader) (int64, error) {
	var bytesRead int64

	var txCount util.VarInt
	n, err := txCount.ReadFrom(r)
	bytesRead += n
	if err != nil {
		return bytesRead, err
	}

	// The smallest possible transaction (version, 0 inputs, 0 outputs, locktime)
	// is 10 bytes.
	if err = guardParseCount(r, uint64(txCount), 10, "transactions"); err != nil {
		return bytesRead, err
	}
	*tt = make([]*Transaction, txCount)

	for i := uint64(0); i < uint64(txCount); i++ {
		tx := new(Transaction)
		n, err := tx.ReadFrom(r)
		bytesRead += n
		if err != nil {
			return bytesRead, err
		}

		(*tt)[i] = tx
	}

	return bytesRead, nil
}

// HasDataOutputs returns true if the transaction has
// at least one data (OP_RETURN) output in it.
func (tx *Transaction) HasDataOutputs() bool {
	for _, out := range tx.Outputs {
		if out.LockingScript.IsData() {
			return true
		}
	}
	return false
}

// InputIdx will return the input at the specified index.
//
// This will consume an overflow error and simply return nil if the input
// isn't found at the index.
func (tx *Transaction) InputIdx(i int) *TransactionInput {
	if i > tx.InputCount()-1 {
		return nil
	}
	return tx.Inputs[i]
}

// OutputIdx will return the output at the specified index.
//
// This will consume an overflow error and simply return nil if the output
// isn't found at the index.
func (tx *Transaction) OutputIdx(i int) *TransactionOutput {
	if i > tx.OutputCount()-1 {
		return nil
	}
	return tx.Outputs[i]
}

// IsCoinbase determines if this transaction is a coinbase by
// checking if the tx input is a standard coinbase input.
func (tx *Transaction) IsCoinbase() bool {
	if len(tx.Inputs) != 1 {
		return false
	}

	cbi := make([]byte, 32)

	if !bytes.Equal(tx.Inputs[0].SourceTXID.CloneBytes(), cbi) {
		return false
	}

	if tx.Inputs[0].SourceTxOutIndex == DefaultSequenceNumber || tx.Inputs[0].SequenceNumber == DefaultSequenceNumber {
		return true
	}

	return false
}

func (tx *Transaction) TxID() *chainhash.Hash {
	if tx.cachedTxID != nil {
		return tx.cachedTxID
	}
	txid, _ := chainhash.NewHash(crypto.Sha256d(tx.Bytes()))
	return txid
}

// SetTxHash sets an optional cached transaction ID that TxID returns without
// recomputation. Use it only when the txid is already known and the transaction
// will not change afterwards -- e.g. a transaction parsed from a trusted source
// that is then read many times, or shared read-only across goroutines after the
// hash is set. TxID never populates or invalidates this cache itself, so a later
// mutation of the transaction would leave a stale value; the caller owns
// invalidation. Pass nil to clear the cache. The returned hash must not be
// mutated. Not safe to call concurrently with TxID on the same transaction.
func (tx *Transaction) SetTxHash(hash *chainhash.Hash) {
	tx.cachedTxID = hash
}

// // TxID returns the transaction ID of the transaction
// // (which is also the transaction hash).
// func (tx *Transaction) TxID() string {
// 	return hex.EncodeToString(util.ReverseBytes(crypto.Sha256d(tx.Bytes())))
// }

// String encodes the transaction into a hex string.
func (tx *Transaction) String() string {
	return hex.EncodeToString(tx.Bytes())
}

// IsValidTxID will check that the txid bytes are valid.
//
// A txid should be of 32 bytes length.
func IsValidTxID(txid []byte) bool {
	return len(txid) == 32
}

// Bytes encodes the transaction into a byte array.
// See https://chainquery.com/bitcoin-cli/decoderawtransaction
func (tx *Transaction) Bytes() []byte {
	return tx.toBytesHelper(0, nil, false)
}

func (tx *Transaction) Hex() string {
	return hex.EncodeToString(tx.Bytes())
}

// EF outputs the transaction into a byte array in extended format
// (with PreviousTxSatoshis and SourceTxScript included)
func (tx *Transaction) EF() ([]byte, error) {
	for _, in := range tx.Inputs {
		if in.SourceTransaction == nil && in.sourceOutput == nil {
			return nil, ErrEmptyPreviousTx
		}
	}
	return tx.toBytesHelper(0, nil, true), nil
}

func (tx *Transaction) EFHex() (string, error) {
	ef, err := tx.EF()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ef), nil
}

// BytesWithClearedInputs encodes the transaction into a byte array but clears its Inputs first.
// This is used when signing transactions.
func (tx *Transaction) BytesWithClearedInputs(index int, lockingScript []byte) []byte {
	return tx.toBytesHelper(index, lockingScript, false)
}

// Clone returns a deep clone of the tx. Consider using ShallowClone if
// you don't need to clone the source transactions.
func (tx *Transaction) Clone() *Transaction {
	// Ignore err as byte slice passed in is created from valid tx
	clone, err := NewTransactionFromBytes(tx.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	for i, input := range tx.Inputs {
		if input.SourceTransaction != nil {
			clone.Inputs[i].SourceTransaction = input.SourceTransaction.Clone()
		}
		// clone.Inputs[i].SourceTransaction = input.SourceTransaction
		clone.Inputs[i].sourceOutput = input.sourceOutput
	}

	return clone
}

func (tx *Transaction) ShallowClone() *Transaction {
	// Creating a new Tx from scratch is much faster than cloning from bytes
	// ~ 420ns/op vs 2200ns/op of the above function in benchmarking
	// this matters as we clone txs a couple of times when verifying signatures
	clone := &Transaction{
		Version:  tx.Version,
		LockTime: tx.LockTime,
		Inputs:   make([]*TransactionInput, len(tx.Inputs)),
		Outputs:  make([]*TransactionOutput, len(tx.Outputs)),
	}

	for i, input := range tx.Inputs {
		clone.Inputs[i] = &TransactionInput{
			SourceTXID:              (*chainhash.Hash)(input.SourceTXID[:]),
			SourceTxOutIndex:        input.SourceTxOutIndex,
			SequenceNumber:          input.SequenceNumber,
			UnlockingScriptTemplate: input.UnlockingScriptTemplate,
		}
		if input.UnlockingScript != nil {
			clone.Inputs[i].UnlockingScript = input.UnlockingScript
		}
		sourceTxOut := input.SourceTxOutput()
		if sourceTxOut != nil {
			clone.Inputs[i].sourceOutput = &TransactionOutput{
				Satoshis:      sourceTxOut.Satoshis,
				LockingScript: script.NewFromBytes(*sourceTxOut.LockingScript),
			}
		}
	}

	for i, output := range tx.Outputs {
		clone.Outputs[i] = &TransactionOutput{
			Satoshis: output.Satoshis,
		}
		if output.LockingScript != nil {
			clone.Outputs[i].LockingScript = output.LockingScript
		}
	}

	return clone
}

func (tx *Transaction) toBytesHelper(index int, lockingScript []byte, extended bool) []byte {
	// Pre-size the buffer exactly, then append each field directly into it via
	// appendBytesHelper. This avoids the per-input/per-output throwaway []byte
	// allocations the previous two-pass implementation made (one Bytes() per
	// element, copied in and discarded). Output bytes are identical; guarded by
	// the golden raw/EF hex tests and the parser fuzz round-trips.
	return tx.appendBytesHelper(make([]byte, 0, tx.serializedSize(index, lockingScript, extended)), index, lockingScript, extended)
}

// appendBytesHelper appends the serialized transaction to h and returns the
// extended slice. It performs no allocation when h has sufficient capacity.
func (tx *Transaction) appendBytesHelper(h []byte, index int, lockingScript []byte, extended bool) []byte {
	h = binary.LittleEndian.AppendUint32(h, tx.Version)

	if extended {
		h = append(h, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEF)
	}

	h = appendVarInt(h, uint64(len(tx.Inputs)))
	for i, in := range tx.Inputs {
		if i == index && lockingScript != nil {
			h = appendVarInt(h, uint64(len(lockingScript)))
			h = append(h, lockingScript...)
		} else {
			h = in.appendTo(h, lockingScript != nil)
		}

		if extended {
			if sourceTxOut := in.SourceTxOutput(); sourceTxOut != nil {
				h = binary.LittleEndian.AppendUint64(h, sourceTxOut.Satoshis)
				h = appendVarInt(h, uint64(len(*sourceTxOut.LockingScript)))
				h = append(h, *sourceTxOut.LockingScript...)
			} else {
				h = binary.LittleEndian.AppendUint64(h, 0)
				h = append(h, 0x00)
			}
		}
	}

	h = appendVarInt(h, uint64(len(tx.Outputs)))
	for _, out := range tx.Outputs {
		h = out.appendTo(h)
	}

	return binary.LittleEndian.AppendUint32(h, tx.LockTime)
}

// AppendBytes appends the raw serialized transaction to dst and returns the
// extended slice. When dst has sufficient spare capacity -- e.g. pre-allocated
// with make([]byte, 0, tx.Size()) -- this performs no heap allocation, letting
// callers serialize many transactions into one reused buffer. The appended
// bytes are identical to Bytes().
func (tx *Transaction) AppendBytes(dst []byte) []byte {
	return tx.appendBytesHelper(dst, 0, nil, false)
}

// WriteTo streams the raw serialized transaction to w, implementing io.WriterTo.
// It writes field by field using only a small stack buffer, so it never
// allocates a copy of the whole transaction (wrap w in a bufio.Writer if it is
// unbuffered). The bytes written are identical to Bytes().
func (tx *Transaction) WriteTo(w io.Writer) (int64, error) {
	var total int64
	var scratch [9]byte

	binary.LittleEndian.PutUint32(scratch[:4], tx.Version)
	if err := writeAll(w, scratch[:4], &total); err != nil {
		return total, err
	}

	n := util.VarInt(uint64(len(tx.Inputs))).PutBytes(scratch[:])
	if err := writeAll(w, scratch[:n], &total); err != nil {
		return total, err
	}
	for _, in := range tx.Inputs {
		if err := in.writeTo(w, scratch[:], &total); err != nil {
			return total, err
		}
	}

	n = util.VarInt(uint64(len(tx.Outputs))).PutBytes(scratch[:])
	if err := writeAll(w, scratch[:n], &total); err != nil {
		return total, err
	}
	for _, out := range tx.Outputs {
		if err := out.writeTo(w, scratch[:], &total); err != nil {
			return total, err
		}
	}

	binary.LittleEndian.PutUint32(scratch[:4], tx.LockTime)
	err := writeAll(w, scratch[:4], &total)
	return total, err
}

// writeAll writes all of b to w, adding the number of bytes written to *total.
// It loops until every byte is written or an error occurs, and returns
// io.ErrShortWrite if the writer accepts no bytes without reporting an error, so
// WriteTo stays correct across writers that only accept partial writes.
func writeAll(w io.Writer, b []byte, total *int64) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		*total += int64(n)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

// Size will return the size of tx in bytes.
func (tx *Transaction) Size() int {
	return tx.serializedSize(0, nil, false)
}

// serializedSize returns the exact number of bytes toBytesHelper will produce
// for the given mode, computed arithmetically without allocating. It is used to
// pre-size the serialization buffer and to implement Size(). The result mirrors
// the raw byte layout of toBytesHelper; TestSizeMatchesSerializedLength locks
// Size() == len(Bytes()).
func (tx *Transaction) serializedSize(index int, lockingScript []byte, extended bool) int {
	size := 4 // version
	if extended {
		size += 6 // extended marker
	}
	size += util.VarInt(uint64(len(tx.Inputs))).Length()
	for i, in := range tx.Inputs {
		if i == index && lockingScript != nil {
			size += util.VarInt(uint64(len(lockingScript))).Length() + len(lockingScript)
		} else {
			size += in.size(lockingScript != nil)
		}
		if extended {
			size += 8 // source satoshis
			if sourceTxOut := in.SourceTxOutput(); sourceTxOut != nil {
				scriptLen := len(*sourceTxOut.LockingScript)
				size += util.VarInt(uint64(scriptLen)).Length() + scriptLen
			} else {
				size++ // zero-length source script varint
			}
		}
	}
	size += util.VarInt(uint64(len(tx.Outputs))).Length()
	for _, out := range tx.Outputs {
		size += out.size()
	}
	size += 4 // locktime
	return size
}

// appendVarInt appends v in Bitcoin VarInt encoding to dst using a stack buffer
// (no allocation). Byte-identical to util.VarInt(v).Bytes().
func appendVarInt(dst []byte, v uint64) []byte {
	var b [9]byte
	n := util.VarInt(v).PutBytes(b[:])
	return append(dst, b[:n]...)
}

func (tx *Transaction) AddMerkleProof(bump *MerklePath) error {
	txid := tx.TxID()
	if !slices.ContainsFunc(bump.Path[0], func(v *PathElement) bool {
		return v.Hash.Equal(*txid)
	}) {
		return ErrBadMerkleProof
	}
	tx.MerklePath = bump
	return nil
}

// Sign signs the transaction with the unlocking script.
func (tx *Transaction) Sign() error {
	err := tx.checkFeeComputed()
	if err != nil {
		return err
	}
	var cache *SigHashCache
	for vin, i := range tx.Inputs {
		if i.UnlockingScriptTemplate == nil {
			continue
		}
		unlock, err := tx.signWithTemplate(i, uint32(vin), &cache)
		if err != nil {
			return err
		}
		i.UnlockingScript = unlock
	}
	return nil
}

// SignUnsigned signs the transaction without the unlocking script.
func (tx *Transaction) SignUnsigned() error {
	err := tx.checkFeeComputed()
	if err != nil {
		return err
	}
	var cache *SigHashCache
	for vin, i := range tx.Inputs {
		if i.UnlockingScript == nil && i.UnlockingScriptTemplate != nil {
			unlock, err := tx.signWithTemplate(i, uint32(vin), &cache)
			if err != nil {
				return err
			}
			i.UnlockingScript = unlock
		}
	}
	return nil
}

// signWithTemplate signs input in with its unlocking-script template. When the
// template implements UnlockingScriptTemplateWithCache the shared BIP143
// SigHashCache is used, built lazily on first use via cache and reused for the
// rest of the signing pass. The cache stays valid across the pass because the
// midstate hashes depend only on the prevouts, sequences and outputs, not on the
// unlocking scripts being assigned as signing proceeds.
func (tx *Transaction) signWithTemplate(in *TransactionInput, vin uint32, cache **SigHashCache) (*script.Script, error) {
	if wc, ok := in.UnlockingScriptTemplate.(UnlockingScriptTemplateWithCache); ok {
		if *cache == nil {
			*cache = tx.NewSigHashCache()
		}
		return wc.SignWithCache(tx, vin, *cache)
	}
	return in.UnlockingScriptTemplate.Sign(tx, vin)
}

func (tx *Transaction) checkFeeComputed() error {
	for _, out := range tx.Outputs {
		if out.Satoshis == 0 && out.Change {
			return errors.New("fee not computed")
		}
	}
	return nil
}

// ToAtomicBEEF serializes this transaction and its inputs into the Atomic BEEF (BRC-95) format.
// The Atomic BEEF format starts with a 4-byte prefix `0x01010101`, followed by the TXID of the subject transaction,
// and then the BEEF data containing only the subject transaction and its dependencies.
// This format ensures that the BEEF structure is atomic and contains no unrelated transactions.
//
// If allowPartial is true, error will not be thrown if there are any missing sourceTransactions.
//
// Returns the serialized Atomic BEEF structure as a byte slice.
// Returns an error if there are any missing sourceTransactions unless allowPartial is true.
func (t *Transaction) AtomicBEEF(allowPartial bool) ([]byte, error) {
	writer := bytes.NewBuffer(nil)

	// Write the Atomic BEEF prefix
	err := binary.Write(writer, binary.LittleEndian, ATOMIC_BEEF)
	if err != nil {
		return nil, err
	}

	// Write the subject TXID (big-endian)
	writer.Write(t.TxID().CloneBytes())

	err = binary.Write(writer, binary.LittleEndian, BEEF_V2)
	if err != nil {
		return nil, err
	}
	bumps := []*MerklePath{}
	bumpMap := map[uint32]int{}
	txid := t.TxID()
	txns := map[chainhash.Hash]*Transaction{*txid: t}
	ancestors, err := t.collectAncestors(txid, txns, allowPartial)
	if err != nil {
		return nil, err
	}
	for _, txid := range ancestors {
		tx := txns[txid]
		if tx.MerklePath == nil {
			continue
		}
		if _, ok := bumpMap[tx.MerklePath.BlockHeight]; !ok {
			bumpMap[tx.MerklePath.BlockHeight] = len(bumps)
			bumps = append(bumps, tx.MerklePath)
		} else {
			err := bumps[bumpMap[tx.MerklePath.BlockHeight]].Combine(tx.MerklePath)
			if err != nil {
				return nil, err
			}
		}
	}

	writer.Write(util.VarInt(len(bumps)).Bytes())
	for _, bump := range bumps {
		writer.Write(bump.Bytes())
	}
	writer.Write(util.VarInt(len(txns)).Bytes())
	for _, txid := range ancestors {
		tx := txns[txid]
		if tx.MerklePath != nil {
			writer.Write([]byte{byte(RawTxAndBumpIndex)})
			writer.Write(util.VarInt(bumpMap[tx.MerklePath.BlockHeight]).Bytes()) //nolint:gosec // G115 -- bump index is bounded by number of BUMPs, always non-negative
		} else {
			writer.Write([]byte{byte(RawTx)})
		}
		writer.Write(tx.Bytes())
	}
	return writer.Bytes(), nil
}

// NewTransactionFromBEEF creates a new Transaction from BEEF bytes.
func NewTransactionFromBEEF(beef []byte) (*Transaction, error) {
	reader := bytes.NewReader(beef)

	var version uint32
	if err := binary.Read(reader, binary.LittleEndian, &version); err != nil {
		return nil, err
	}

	switch version {
	case ATOMIC_BEEF:
		b, txid, err := NewBeefFromAtomicBytes(beef)
		if err != nil {
			return nil, err
		}
		tx := b.FindAtomicTransactionByHash(txid)
		if tx == nil {
			return nil, fmt.Errorf("atomic BEEF raw subject %s is unavailable", txid.String())
		}
		return tx, nil
	case BEEF_V1:
		BUMPs, err := readBUMPs(reader)
		if err != nil {
			return nil, err
		}

		transaction, err := readTransactionsGetLast(reader, BUMPs)
		if err != nil {
			return nil, err
		}

		return transaction, nil
	default:
		return nil, fmt.Errorf("use NewBeefFromBytes to parse anything which isn't V1 BEEF or AtomicBEEF")
	}
}
