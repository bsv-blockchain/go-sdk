package transaction

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/pkg/errors"

	script "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/util"
)

/*
General format (inside a block) of each output of a transaction - Txout
Field	                        Description	                                Size
-----------------------------------------------------------------------------------------------------
value                         non-negative integer giving the number of   8 bytes
                              Satoshis(BTC/10^8) to be transferred
Txout-script length           non-negative integer                        1 - 9 bytes VI = util.VarInt
Txout-script / scriptPubKey   Script                                      <out-script length>-many bytes
(lockingScript)

*/

// TransactionOutput is a representation of a transaction output
type TransactionOutput struct {
	Satoshis      uint64         `json:"satoshis"`
	LockingScript *script.Script `json:"locking_script"`
	Change        bool           `json:"change"`
}

// ReadFrom reads from the `io.Reader` into the `transaction.TransactionOutput`.
func (o *TransactionOutput) ReadFrom(r io.Reader) (int64, error) {
	return o.readFrom(r, make([]byte, 32))
}

// readFrom decodes a single output from r using the caller's reusable scratch
// buffer (len >= 8), so a whole transaction parses with one header allocation.
// The satoshi field is read into scratch and parsed immediately; the locking
// script keeps its own retained allocation because script.NewFromBytes aliases
// it.
func (o *TransactionOutput) readFrom(r io.Reader, scratch []byte) (int64, error) {
	*o = TransactionOutput{}
	var bytesRead int64

	n, err := io.ReadFull(r, scratch[:8])
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, errors.Wrapf(err, "satoshis(8): got %d bytes", n)
	}
	o.Satoshis = binary.LittleEndian.Uint64(scratch[:8])

	scriptLen, n64, err := readVarInt(r, scratch)
	bytesRead += n64
	if err != nil {
		return bytesRead, err
	}

	scriptBytes, n, err := readGuardedBytes(r, scriptLen, "output locking script")
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, errors.Wrapf(err, "lockingScript(%d): got %d bytes", scriptLen, n)
	}
	o.LockingScript = script.NewFromBytes(scriptBytes)

	return bytesRead, nil
}

// LockingScriptHex returns the locking script
// of an output encoded as a hex string.
func (o *TransactionOutput) LockingScriptHex() string {
	return hex.EncodeToString(*o.LockingScript)
}

func (o *TransactionOutput) String() string {
	return fmt.Sprintf(`value:     %d
scriptLen: %d
script:    %s
`, o.Satoshis, len(*o.LockingScript), o.LockingScript)
}

// Bytes encodes the Output into a byte array.
func (o *TransactionOutput) Bytes() []byte {
	return o.appendTo(make([]byte, 0, o.size()))
}

// appendTo appends the serialized output to buf and returns the extended slice,
// matching Bytes(). It performs no allocation when buf has capacity.
func (o *TransactionOutput) appendTo(buf []byte) []byte {
	buf = binary.LittleEndian.AppendUint64(buf, o.Satoshis)
	buf = appendVarInt(buf, uint64(len(*o.LockingScript)))
	buf = append(buf, *o.LockingScript...)
	return buf
}

// writeTo streams the raw serialized output to w (matching Bytes()) using
// scratch (len >= 9) as a stack buffer, adding the bytes written to *total.
func (o *TransactionOutput) writeTo(w io.Writer, scratch []byte, total *int64) error {
	binary.LittleEndian.PutUint64(scratch[:8], o.Satoshis)
	if err := writeAll(w, scratch[:8], total); err != nil {
		return err
	}
	n := util.VarInt(uint64(len(*o.LockingScript))).PutBytes(scratch)
	if err := writeAll(w, scratch[:n], total); err != nil {
		return err
	}
	return writeAll(w, *o.LockingScript, total)
}

// size returns the serialized length of the output in bytes, matching
// Bytes(), without allocating.
func (o *TransactionOutput) size() int {
	scriptLen := len(*o.LockingScript)
	return 8 + util.VarInt(uint64(scriptLen)).Length() + scriptLen
}

// BytesForSigHash returns the proper serialization
// of an output to be hashed and signed (sighash). This is the standard output
// serialization (identical to Bytes()).
func (o *TransactionOutput) BytesForSigHash() []byte {
	return o.appendTo(make([]byte, 0, o.size()))
}
