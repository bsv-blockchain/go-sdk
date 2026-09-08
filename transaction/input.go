package transaction

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/pkg/errors"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	script "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/util"
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
	if i.SourceTransaction != nil && int(i.SourceTxOutIndex) < len(i.SourceTransaction.Outputs) {
		return i.SourceTransaction.Outputs[i.SourceTxOutIndex]
	}
	// The source transaction does not carry the output this input spends. Fall
	// back to any output supplied directly; callers already handle nil, whereas
	// indexing here panicked.
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
	return i.readFrom(r, false, make([]byte, 32))
}

// ReadFromExtended reads the `io.Reader` into the `transaction.TransactionInput` when the reader is
// consuming an extended format transaction.
func (i *TransactionInput) ReadFromExtended(r io.Reader) (int64, error) {
	return i.readFrom(r, true, make([]byte, 32))
}

// readFrom decodes a single input from r. scratch (len >= 32) is a reusable
// buffer, supplied by the caller so a whole transaction parses with one header
// allocation: each fixed-size field is read into it and parsed immediately
// (chainhash.NewHash copies, binary.LittleEndian reads in place) before the next
// read reuses it. Script bytes get their own retained allocation because
// script.NewFromBytes aliases them.
func (i *TransactionInput) readFrom(r io.Reader, extended bool, scratch []byte) (int64, error) {
	*i = TransactionInput{}
	var bytesRead int64

	n, err := io.ReadFull(r, scratch[:32])
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, errors.Wrapf(err, "previousTxID(32): got %d bytes", n)
	}
	if i.SourceTXID, err = chainhash.NewHash(scratch[:32]); err != nil {
		return bytesRead, errors.Wrap(err, "failed to create chainhash from previousTxID")
	}

	n, err = io.ReadFull(r, scratch[:4])
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, errors.Wrapf(err, "previousTxID(4): got %d bytes", n)
	}
	i.SourceTxOutIndex = binary.LittleEndian.Uint32(scratch[:4])

	scriptLen, n64, err := readVarInt(r, scratch)
	bytesRead += n64
	if err != nil {
		return bytesRead, err
	}
	scriptBytes, n, err := readGuardedBytes(r, scriptLen, "input script")
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, errors.Wrapf(err, "script(%d): got %d bytes", scriptLen, n)
	}
	i.UnlockingScript = script.NewFromBytes(scriptBytes)

	n, err = io.ReadFull(r, scratch[:4])
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, errors.Wrapf(err, "sequence(4): got %d bytes", n)
	}
	i.SequenceNumber = binary.LittleEndian.Uint32(scratch[:4])

	if extended {
		n, err = io.ReadFull(r, scratch[:8])
		bytesRead += int64(n)
		if err != nil {
			return bytesRead, errors.Wrapf(err, "prevSatoshis(8): got %d bytes", n)
		}
		satoshis := binary.LittleEndian.Uint64(scratch[:8])

		// Read in the prevTxLockingScript
		srcScriptLen, n64, err := readVarInt(r, scratch)
		bytesRead += n64
		if err != nil {
			return bytesRead, err
		}

		scriptBytes, n, err := readGuardedBytes(r, srcScriptLen, "input source script")
		bytesRead += int64(n)
		if err != nil {
			return bytesRead, errors.Wrapf(err, "script(%d): got %d bytes", util.VarInt(srcScriptLen).Length(), n)
		}

		i.SetSourceTxOutput(&TransactionOutput{
			Satoshis:      satoshis,
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

// Bytes encodes the Input into a byte array.
func (i *TransactionInput) Bytes(clearScript bool) []byte {
	return i.appendTo(make([]byte, 0, i.size(clearScript)), clearScript)
}

// appendTo appends the serialized input to buf and returns the extended slice,
// matching Bytes(clearScript). It performs no allocation when buf has capacity.
func (i *TransactionInput) appendTo(buf []byte, clearScript bool) []byte {
	buf = append(buf, i.SourceTXID[:]...)
	buf = binary.LittleEndian.AppendUint32(buf, i.SourceTxOutIndex)
	if clearScript || i.UnlockingScript == nil {
		buf = append(buf, 0x00)
	} else {
		buf = appendVarInt(buf, uint64(len(*i.UnlockingScript)))
		buf = append(buf, *i.UnlockingScript...)
	}
	buf = binary.LittleEndian.AppendUint32(buf, i.SequenceNumber)
	return buf
}

// writeTo streams the raw serialized input to w (matching Bytes(false)) using
// scratch (len >= 9) as a stack buffer, adding the bytes written to *total.
func (i *TransactionInput) writeTo(w io.Writer, scratch []byte, total *int64) error {
	if err := writeAll(w, i.SourceTXID[:], total); err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(scratch[:4], i.SourceTxOutIndex)
	if err := writeAll(w, scratch[:4], total); err != nil {
		return err
	}
	if i.UnlockingScript == nil {
		scratch[0] = 0x00
		if err := writeAll(w, scratch[:1], total); err != nil {
			return err
		}
	} else {
		n := util.VarInt(uint64(len(*i.UnlockingScript))).PutBytes(scratch)
		if err := writeAll(w, scratch[:n], total); err != nil {
			return err
		}
		if err := writeAll(w, *i.UnlockingScript, total); err != nil {
			return err
		}
	}
	binary.LittleEndian.PutUint32(scratch[:4], i.SequenceNumber)
	return writeAll(w, scratch[:4], total)
}

// size returns the serialized length of the input in bytes, matching
// Bytes(clearScript), without allocating.
func (i *TransactionInput) size(clearScript bool) int {
	if clearScript || i.UnlockingScript == nil {
		return 32 + 4 + 1 + 4 // txid + index + empty-script varint + sequence
	}
	scriptLen := len(*i.UnlockingScript)
	return 32 + 4 + util.VarInt(uint64(scriptLen)).Length() + scriptLen + 4
}

func (i *TransactionInput) SetSourceTxOutput(txo *TransactionOutput) {
	i.sourceOutput = txo
}
