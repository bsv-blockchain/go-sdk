package transaction

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"slices"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/pkg/errors"
)

type Transaction struct {
	Version    uint32               `json:"version"`
	Inputs     []*TransactionInput  `json:"inputs"`
	Outputs    []*TransactionOutput `json:"outputs"`
	LockTime   uint32               `json:"locktime"`
	MerklePath *MerklePath          `json:"merklePath"`
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

	version := make([]byte, 4)
	n, err := io.ReadFull(r, version)
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, err
	}

	tx.Version = binary.LittleEndian.Uint32(version)

	extended := false

	var inputCount VarInt

	n64, err = inputCount.ReadFrom(r)
	bytesRead += n64
	if err != nil {
		return bytesRead, err
	}

	var outputCount VarInt
	locktime := make([]byte, 4)

	// ----------------------------------------------------------------------------------
	// If the inputCount is 0, we may be parsing an incomplete transaction, or we may be
	// both of these cases without needing to rewind (peek) the incoming stream of bytes.
	// ----------------------------------------------------------------------------------
	if inputCount == 0 {
		n64, err = outputCount.ReadFrom(r)
		bytesRead += n64
		if err != nil {
			return bytesRead, err
		}

		if outputCount == 0 {
			// Read in lock time
			n, err = io.ReadFull(r, locktime)
			bytesRead += int64(n)
			if err != nil {
				return bytesRead, err
			}

			if binary.BigEndian.Uint32(locktime) != 0xEF {
				tx.LockTime = binary.LittleEndian.Uint32(locktime)
				return bytesRead, nil
			}

			extended = true

			n64, err = inputCount.ReadFrom(r)
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
	for i := uint64(0); i < uint64(inputCount); i++ {
		input := &TransactionInput{}
		n64, err = input.readFrom(r, extended)
		bytesRead += n64
		if err != nil {
			return bytesRead, err
		}
		tx.Inputs = append(tx.Inputs, input)
	}

	if inputCount > 0 || extended {
		// Re-read the actual output count...
		n64, err = outputCount.ReadFrom(r)
		bytesRead += n64
		if err != nil {
			return bytesRead, err
		}
	}

	for i := uint64(0); i < uint64(outputCount); i++ {
		output := new(TransactionOutput)
		n64, err = output.ReadFrom(r)
		bytesRead += n64
		if err != nil {
			return bytesRead, err
		}

		tx.Outputs = append(tx.Outputs, output)
	}

	n, err = io.ReadFull(r, locktime)
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, err
	}
	tx.LockTime = binary.LittleEndian.Uint32(locktime)

	return bytesRead, nil
}

// ReadFrom txs from a block in a `transaction.Transactions`. This assumes a preceding varint detailing
// the total number of txs that the reader will provide.
func (tt *Transactions) ReadFrom(r io.Reader) (int64, error) {
	var bytesRead int64

	var txCount VarInt
	n, err := txCount.ReadFrom(r)
	bytesRead += n
	if err != nil {
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
	txid, _ := chainhash.NewHash(crypto.Sha256d(tx.Bytes()))
	return txid
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
	h := make([]byte, 0)

	h = append(h, util.LittleEndianBytes(tx.Version, 4)...)

	if extended {
		h = append(h, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0xEF}...)
	}

	h = append(h, VarInt(uint64(len(tx.Inputs))).Bytes()...)

	for i, in := range tx.Inputs {
		s := in.Bytes(lockingScript != nil)
		if i == index && lockingScript != nil {
			h = append(h, VarInt(uint64(len(lockingScript))).Bytes()...)
			h = append(h, lockingScript...)
		} else {
			h = append(h, s...)
		}

		if extended {
			b := make([]byte, 8)
			sourceTxOut := in.SourceTxOutput()
			if sourceTxOut != nil {
				binary.LittleEndian.PutUint64(b, sourceTxOut.Satoshis)
				h = append(h, b...)
				l := uint64(len(*sourceTxOut.LockingScript))
				h = append(h, VarInt(l).Bytes()...)
				h = append(h, *sourceTxOut.LockingScript...)
			} else {
				binary.LittleEndian.PutUint64(b, 0)
				h = append(h, b...)
				h = append(h, 0x00) // The length of the script is zero
			}
		}
	}

	h = append(h, VarInt(uint64(len(tx.Outputs))).Bytes()...)
	for _, out := range tx.Outputs {
		h = append(h, out.Bytes()...)
	}

	lt := make([]byte, 4)
	binary.LittleEndian.PutUint32(lt, tx.LockTime)

	return append(h, lt...)
}

// Size will return the size of tx in bytes.
func (tx *Transaction) Size() int {
	return len(tx.Bytes())
}

func (tx *Transaction) AddMerkleProof(bump *MerklePath) error {
	if !slices.ContainsFunc(bump.Path[0], func(v *PathElement) bool {
		return v.Hash.Equal(*tx.TxID())
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
	for vin, i := range tx.Inputs {
		if i.UnlockingScriptTemplate != nil {
			unlock, err := i.UnlockingScriptTemplate.Sign(tx, uint32(vin))
			if err != nil {
				return err
			}
			i.UnlockingScript = unlock
		}
	}
	return nil
}

// SignUnsigned signs the transaction without the unlocking script.
func (tx *Transaction) SignUnsigned() error {
	err := tx.checkFeeComputed()
	if err != nil {
		return err
	}
	for vin, i := range tx.Inputs {
		if i.UnlockingScript == nil {
			if i.UnlockingScriptTemplate != nil {
				unlock, err := i.UnlockingScriptTemplate.Sign(tx, uint32(vin))
				if err != nil {
					return err
				}
				i.UnlockingScript = unlock
			}
		}
	}
	return nil
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
	txid := t.TxID().CloneBytes()
	writer.Write(txid)

	err = binary.Write(writer, binary.LittleEndian, BEEF_V2)
	if err != nil {
		return nil, err
	}
	bumps := []*MerklePath{}
	bumpMap := map[uint32]int{}
	txns := map[string]*Transaction{t.TxID().String(): t}
	ancestors, err := t.collectAncestors(txns, allowPartial)
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

	writer.Write(VarInt(len(bumps)).Bytes())
	for _, bump := range bumps {
		writer.Write(bump.Bytes())
	}
	writer.Write(VarInt(len(txns)).Bytes())
	for _, txid := range ancestors {
		tx := txns[txid]
		if tx.MerklePath != nil {
			writer.Write([]byte{byte(RawTxAndBumpIndex)})
			writer.Write(VarInt(bumpMap[tx.MerklePath.BlockHeight]).Bytes())
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

	if version == ATOMIC_BEEF {
		hash := make([]byte, 32)
		if _, err := io.ReadFull(reader, hash); err != nil {
			return nil, err
		} else if b, err := NewBeefFromBytes(beef[36:]); err != nil {
			return nil, err
		} else if txid, err := chainhash.NewHash(hash); err != nil {
			return nil, err
		} else {
			return b.FindAtomicTransaction(txid.String()), nil
		}
	} else if version == BEEF_V1 {
		BUMPs, err := readBUMPs(reader)
		if err != nil {
			return nil, err
		}

		transaction, err := readTransactionsGetLast(reader, BUMPs)
		if err != nil {
			return nil, err
		}

		return transaction, nil
	} else {
		return nil, fmt.Errorf("use NewBeefFromBytes to parse anything which isn't V1 BEEF or AtomicBEEF")
	}

}
