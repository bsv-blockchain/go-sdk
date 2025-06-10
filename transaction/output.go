package transaction

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	script "github.com/bsv-blockchain/go-sdk/v2/script"
	"github.com/bsv-blockchain/go-sdk/v2/util"
	"github.com/pkg/errors"
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
	*o = TransactionOutput{}
	var bytesRead int64

	satoshis := make([]byte, 8)
	n, err := io.ReadFull(r, satoshis)
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, errors.Wrapf(err, "satoshis(8): got %d bytes", n)
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
		return bytesRead, errors.Wrapf(err, "lockingScript(%d): got %d bytes", l, n)
	}

	o.Satoshis = binary.LittleEndian.Uint64(satoshis)
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
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, o.Satoshis)

	h := make([]byte, 0)
	h = append(h, b...)
	h = append(h, util.VarInt(uint64(len(*o.LockingScript))).Bytes()...)
	h = append(h, *o.LockingScript...)

	return h
}

// BytesForSigHash returns the proper serialization
// of an output to be hashed and signed (sighash).
func (o *TransactionOutput) BytesForSigHash() []byte {
	buf := make([]byte, 0)

	satoshis := make([]byte, 8)
	binary.LittleEndian.PutUint64(satoshis, o.Satoshis)
	buf = append(buf, satoshis...)

	buf = append(buf, util.VarInt(uint64(len(*o.LockingScript))).Bytes()...)
	buf = append(buf, *o.LockingScript...)

	return buf
}
