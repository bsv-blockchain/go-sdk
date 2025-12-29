package transaction

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	script "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/pkg/errors"
)

/*
Field	                     Description                                                   Size
--------------------------------------------------------------------------------------------------------
Previous Transaction hash  doubled SHA256-hashed of a (previous) to-be-used transaction	 32 bytes
Previous Txout-index       non-negative integer indexing an output of the to-be-used      4 bytes
                           transaction
Txin-script length         non-negative integer VI = util.VarInt                               1-9 bytes
Txin-script / scriptSig	   Script	                                                        <in-script length>-many bytes
sequence_no	               normally 0xFFFFFFFF; irrelevant unless transaction's           4 bytes
                           lock_time is > 0
*/

// DefaultSequenceNumber is the default starting sequence number
const DefaultSequenceNumber uint32 = 0xFFFFFFFF

// TransactionInput is a representation of a transaction input
//
// DO NOT CHANGE ORDER - Optimized for memory via maligned
type TransactionInput struct {
	SourceTXID              *chainhash.Hash
	UnlockingScript         *script.Script
	SourceTxOutIndex        uint32
	SequenceNumber          uint32
	SourceTransaction       *Transaction
	sourceOutput            *TransactionOutput
	UnlockingScriptTemplate UnlockingScriptTemplate
}

func (i *TransactionInput) SourceTxOutput() *TransactionOutput {
	if i.SourceTransaction != nil {
		return i.SourceTransaction.Outputs[i.SourceTxOutIndex]
	}
	return i.sourceOutput
}

func (i *TransactionInput) SourceTxScript() *script.Script {
	sourceTxOut := i.SourceTxOutput()
	if sourceTxOut != nil {
		return sourceTxOut.LockingScript
	}
	return nil
}

func (i *TransactionInput) SourceTxSatoshis() *uint64 {
	sourceTxOut := i.SourceTxOutput()
	if sourceTxOut != nil {
		return &sourceTxOut.Satoshis
	}
	return nil
}

// ReadFrom reads from the `io.Reader` into the `transaction.TransactionInput`.
func (i *TransactionInput) ReadFrom(r io.Reader) (int64, error) {
	return i.readFrom(r, false)
}

// ReadFromExtended reads the `io.Reader` into the `transaction.TransactionInput` when the reader is
// consuming an extended format transaction.
func (i *TransactionInput) ReadFromExtended(r io.Reader) (int64, error) {
	return i.readFrom(r, true)
}

func (i *TransactionInput) readFrom(r io.Reader, extended bool) (int64, error) {
	*i = TransactionInput{}
	var bytesRead int64

	previousTxID := make([]byte, 32)
	n, err := io.ReadFull(r, previousTxID)
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, errors.Wrapf(err, "previousTxID(32): got %d bytes", n)
	}

	prevIndex := make([]byte, 4)
	n, err = io.ReadFull(r, prevIndex)
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, errors.Wrapf(err, "previousTxID(4): got %d bytes", n)
	}

	var l util.VarInt
	n64, err := l.ReadFrom(r)
	bytesRead += n64
	if err != nil {
		return bytesRead, err
	}

	scriptBytes := make([]byte, l)
	n, err = io.ReadFull(r, scriptBytes)
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, errors.Wrapf(err, "script(%d): got %d bytes", l, n)
	}

	sequence := make([]byte, 4)
	n, err = io.ReadFull(r, sequence)
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, errors.Wrapf(err, "sequence(4): got %d bytes", n)
	}

	if i.SourceTXID, err = chainhash.NewHash(previousTxID); err != nil {
		return bytesRead, errors.Wrap(err, "failed to create chainhash from previousTxID")
	}
	i.SourceTxOutIndex = binary.LittleEndian.Uint32(prevIndex)
	i.UnlockingScript = script.NewFromBytes(scriptBytes)
	i.SequenceNumber = binary.LittleEndian.Uint32(sequence)

	if extended {
		prevSatoshis := make([]byte, 8)
		n, err = io.ReadFull(r, prevSatoshis)
		bytesRead += int64(n)
		if err != nil {
			return bytesRead, errors.Wrapf(err, "prevSatoshis(8): got %d bytes", n)
		}

		// Read in the prevTxLockingScript
		var scriptLen util.VarInt
		n64, err := scriptLen.ReadFrom(r)
		bytesRead += n64
		if err != nil {
			return bytesRead, err
		}

		scriptBytes := make([]byte, scriptLen)
		n, err := io.ReadFull(r, scriptBytes)
		bytesRead += int64(n)
		if err != nil {
			return bytesRead, errors.Wrapf(err, "script(%d): got %d bytes", scriptLen.Length(), n)
		}

		i.SetSourceTxOutput(&TransactionOutput{
			Satoshis:      binary.LittleEndian.Uint64(prevSatoshis),
			LockingScript: script.NewFromBytes(scriptBytes),
		})
	}

	return bytesRead, nil
}

// String implements the Stringer interface and returns a string
// representation of a transaction input.
func (i *TransactionInput) String() string {
	return fmt.Sprintf(
		`sourceTxHash:   %s
sourceOutIndex: %d
scriptLen:    %d
script:       %s
sequence:     %x
`,
		i.SourceTXID.String(),
		i.SourceTxOutIndex,
		len(*i.UnlockingScript),
		i.UnlockingScript,
		i.SequenceNumber,
	)
}

// Bytes encodes the Input into a hex byte array.
func (i *TransactionInput) Bytes(clear bool) []byte {
	// Calculate total size: 32 (txid) + 4 (index) + varint + script + 4 (sequence)
	var scriptLen int
	var varInt util.VarInt
	var varIntLen int
	if clear || i.UnlockingScript == nil {
		varIntLen = 1
		scriptLen = 0
	} else {
		scriptLen = len(*i.UnlockingScript)
		varInt = util.VarInt(uint64(scriptLen))
		varIntLen = varInt.Length()
	}
	totalLen := 32 + 4 + varIntLen + scriptLen + 4

	h := make([]byte, totalLen)
	copy(h[0:32], i.SourceTXID.CloneBytes())
	binary.LittleEndian.PutUint32(h[32:36], i.SourceTxOutIndex)

	offset := 36
	if clear || i.UnlockingScript == nil {
		h[offset] = 0x00
		offset++
	} else {
		varInt.PutBytes(h[offset:])
		offset += varIntLen
		copy(h[offset:], *i.UnlockingScript)
		offset += scriptLen
	}

	binary.LittleEndian.PutUint32(h[offset:], i.SequenceNumber)
	return h
}

func (i *TransactionInput) SetSourceTxOutput(txo *TransactionOutput) {
	i.sourceOutput = txo
}
