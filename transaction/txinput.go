package transaction

import (
	"encoding/binary"

	"github.com/bsv-blockchain/go-sdk/v2/chainhash"
	crypto "github.com/bsv-blockchain/go-sdk/v2/primitives/hash"
	script "github.com/bsv-blockchain/go-sdk/v2/script"
)

// TotalInputSatoshis returns the total Satoshis inputted to the transaction.
func (tx *Transaction) TotalInputSatoshis() (total uint64, err error) {
	for _, in := range tx.Inputs {
		prevSats := uint64(0)
		if in.SourceTxSatoshis() == nil {
			return 0, ErrEmptyPreviousTx
		} else {
			prevSats = *in.SourceTxSatoshis()
		}
		total += prevSats
	}
	return
}

func (tx *Transaction) AddInput(input *TransactionInput) {
	tx.Inputs = append(tx.Inputs, input)
}

func (tx *Transaction) AddInputWithOutput(input *TransactionInput, output *TransactionOutput) {
	input.SetSourceTxOutput(output)
	tx.Inputs = append(tx.Inputs, input)
}

func (tx *Transaction) AddInputFromTx(sourceTx *Transaction, vout uint32,
	unlockingScriptTemplate UnlockingScriptTemplate) {
	i := &TransactionInput{
		SourceTXID:              sourceTx.TxID(),
		SourceTxOutIndex:        vout,
		SourceTransaction:       sourceTx,
		SequenceNumber:          DefaultSequenceNumber, // use default finalized sequence number
		UnlockingScriptTemplate: unlockingScriptTemplate,
	}

	tx.Inputs = append(tx.Inputs, i)
}

// InputCount returns the number of transaction Inputs.
func (tx *Transaction) InputCount() int {
	return len(tx.Inputs)
}

// SourceOutHash returns a byte slice of inputs outpoints, for creating a signature hash
func (tx *Transaction) SourceOutHash() *chainhash.Hash {
	buf := make([]byte, 0, len(tx.Inputs)*36)

	oi := make([]byte, 4)
	for _, in := range tx.Inputs {
		buf = append(buf, in.SourceTXID[:]...)
		binary.LittleEndian.PutUint32(oi, in.SourceTxOutIndex)
		buf = append(buf, oi...)
	}

	hash, _ := chainhash.NewHash(crypto.Sha256d(buf))
	return hash
}

// SequenceHash returns a byte slice of inputs SequenceNumber, for creating a signature hash
func (tx *Transaction) SequenceHash() []byte {
	buf := make([]byte, 0, len(tx.Inputs)*4)

	oi := make([]byte, 4)
	for _, in := range tx.Inputs {
		binary.LittleEndian.PutUint32(oi, in.SequenceNumber)
		buf = append(buf, oi...)
	}

	return crypto.Sha256d(buf)
}

// AddInputFrom adds a new input to the transaction from the specified UTXO fields, using the default
// finalized sequence number (0xFFFFFFFF). If you want a different nSeq, change it manually
// afterwards.
func (tx *Transaction) AddInputFrom(prevTxID string, vout uint32, prevTxLockingScript string,
	satoshis uint64, unlockingScriptTemplate UnlockingScriptTemplate) error {
	pts, err := script.NewFromHex(prevTxLockingScript)
	if err != nil {
		return err
	}
	pti, err := chainhash.NewHashFromHex(prevTxID)
	if err != nil {
		return err
	}

	return tx.AddInputsFromUTXOs(&UTXO{
		TxID:                    pti,
		Vout:                    vout,
		LockingScript:           pts,
		Satoshis:                satoshis,
		UnlockingScriptTemplate: unlockingScriptTemplate,
	})
}

// AddInputsFromUTXOs adds a new input to the transaction from the specified *transaction.UTXO fields, using the default
// finalized sequence number (0xFFFFFFFF). If you want a different nSeq, change it manually
// afterwards.
func (tx *Transaction) AddInputsFromUTXOs(utxos ...*UTXO) error {
	for _, utxo := range utxos {
		i := &TransactionInput{
			SourceTXID:              utxo.TxID,
			SourceTxOutIndex:        utxo.Vout,
			SequenceNumber:          DefaultSequenceNumber, // use default finalized sequence number
			UnlockingScriptTemplate: utxo.UnlockingScriptTemplate,
		}
		i.SetSourceTxOutput(&TransactionOutput{
			Satoshis:      utxo.Satoshis,
			LockingScript: utxo.LockingScript,
		})

		tx.AddInput(i)
	}

	return nil
}
