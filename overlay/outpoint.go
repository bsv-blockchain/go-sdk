package overlay

import (
	"database/sql/driver"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/util"
)

type Outpoint struct {
	Txid *chainhash.Hash
	Vout uint32
}

func NewOutpointFromTxBytes(b [36]byte) (o *Outpoint) {
	o = &Outpoint{
		Vout: binary.LittleEndian.Uint32(b[32:]),
	}
	o.Txid, _ = chainhash.NewHash(b[:32])
	return
}

func (o *Outpoint) TxBytes() []byte {
	return binary.LittleEndian.AppendUint32(o.Txid.CloneBytes(), o.Vout)
}

func NewOutpointFromBytes(b [36]byte) (o *Outpoint) {
	o = &Outpoint{
		Vout: binary.BigEndian.Uint32(b[32:]),
	}
	o.Txid, _ = chainhash.NewHash(util.ReverseBytes(b[:32]))
	return
}

func (o *Outpoint) Bytes() []byte {
	return binary.BigEndian.AppendUint32(util.ReverseBytes(o.Txid.CloneBytes()), o.Vout)
}

func NewOutpointFromString(s string) (o *Outpoint, err error) {
	if len(s) < 66 {
		return nil, fmt.Errorf("invalid-string")
	}

	o = &Outpoint{}
	if o.Txid, err = chainhash.NewHashFromHex(s[:64]); err == nil {
		if vout, err := strconv.ParseUint(s[65:], 10, 32); err == nil {
			o.Vout = uint32(vout)
		}
	}
	return
}

func (o *Outpoint) String() string {
	return fmt.Sprintf("%x_%d", o.Txid.String(), o.Vout)
}

func (o Outpoint) MarshalJSON() (bytes []byte, err error) {
	return json.Marshal(o.String())
}

func (o *Outpoint) UnmarshalJSON(data []byte) error {
	var x string
	err := json.Unmarshal(data, &x)
	if err != nil {
		return err
	} else if op, err := NewOutpointFromString(x); err != nil {
		return err
	} else {
		*o = *op
		return nil
	}
}

func (o Outpoint) Value() (driver.Value, error) {
	return o.Bytes(), nil
}

func (o *Outpoint) Scan(value interface{}) error {
	if b, ok := value.([]byte); !ok || len(b) != 36 {
		return fmt.Errorf("invalid-outpoint")
	} else {
		op := NewOutpointFromBytes([36]byte(b))
		*o = *op
		return nil
	}
}
