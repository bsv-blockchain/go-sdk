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

// Outpoint represents a transaction output reference consisting of a transaction ID and output index
type Outpoint struct {
	Txid        chainhash.Hash `json:"txid"`
	OutputIndex uint32         `json:"outputIndex"`
}

// NewOutpoint creates a new Outpoint with the given transaction ID and output index
func NewOutpoint(txid chainhash.Hash, outputIndex uint32) *Outpoint {
	return &Outpoint{
		Txid:        txid,
		OutputIndex: outputIndex,
	}
}

// NewOutpointFromTxBytes creates a new Outpoint from a 36-byte array in transaction byte format (little-endian)
func NewOutpointFromTxBytes(b [36]byte) (o *Outpoint) {
	o = &Outpoint{
		OutputIndex: binary.LittleEndian.Uint32(b[32:]),
	}
	txid, _ := chainhash.NewHash(b[:32])
	o.Txid = *txid
	return
}

// Equal returns true if this outpoint is equal to another outpoint
func (o *Outpoint) Equal(other *Outpoint) bool {
	return o.Txid.Equal(other.Txid) && o.OutputIndex == other.OutputIndex
}

// TxBytes returns the outpoint as a byte slice in transaction format (little-endian)
func (o *Outpoint) TxBytes() []byte {
	return binary.LittleEndian.AppendUint32(o.Txid.CloneBytes(), o.OutputIndex)
}

// NewOutpointFromBytes creates a new Outpoint from a 36-byte array in standard byte format (big-endian)
func NewOutpointFromBytes(b [36]byte) (o *Outpoint) {
	o = &Outpoint{
		OutputIndex: binary.BigEndian.Uint32(b[32:]),
	}
	txid, _ := chainhash.NewHash(util.ReverseBytes(b[:32]))
	o.Txid = *txid
	return
}

// Bytes returns the outpoint as a byte slice in standard format (big-endian)
func (o *Outpoint) Bytes() []byte {
	return binary.BigEndian.AppendUint32(util.ReverseBytes(o.Txid.CloneBytes()), o.OutputIndex)
}

// NewOutpointFromString creates a new Outpoint from a string in the format "txid.outputIndex"
func NewOutpointFromString(s string) (*Outpoint, error) {
	if len(s) < 66 {
		return nil, fmt.Errorf("invalid-string")
	}

	o := &Outpoint{}
	if txid, err := chainhash.NewHashFromHex(s[:64]); err != nil {
		return nil, err
	} else {
		o.Txid = *txid
		if vout, err := strconv.ParseUint(s[65:], 10, 32); err != nil {
			return nil, err
		} else {
			o.OutputIndex = uint32(vout)
		}
	}
	return o, nil
}

// String returns the outpoint as a string in the format "txid.outputIndex"
func (o *Outpoint) String() string {
	return fmt.Sprintf("%s.%d", o.Txid.String(), o.OutputIndex)
}

// OrdinalString returns the outpoint as a string in ordinal format "txid_outputIndex"
func (o *Outpoint) OrdinalString() string {
	return fmt.Sprintf("%s_%d", o.Txid.String(), o.OutputIndex)
}

// MarshalJSON implements the json.Marshaler interface
func (o Outpoint) MarshalJSON() (bytes []byte, err error) {
	return json.Marshal(o.String())
}

// UnmarshalJSON implements the json.Unmarshaler interface
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

// Value implements the driver.Valuer interface for database storage
func (o Outpoint) Value() (driver.Value, error) {
	return o.Bytes(), nil
}

// Scan implements the sql.Scanner interface for database retrieval
func (o *Outpoint) Scan(value any) error {
	if b, ok := value.([]byte); !ok || len(b) != 36 {
		return fmt.Errorf("invalid-outpoint")
	} else {
		op := NewOutpointFromBytes([36]byte(b))
		*o = *op
		return nil
	}
}
