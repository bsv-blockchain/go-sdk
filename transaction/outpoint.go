package transaction

import (
	"database/sql/driver"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/bsv-blockchain/go-sdk/chainhash"
)

// Outpoint represents a transaction output reference consisting of a transaction ID and output index
type Outpoint struct {
	Txid  chainhash.Hash `json:"txid"`
	Index uint32         `json:"index"`
}

// Equal returns true if this outpoint is equal to another outpoint
func (o *Outpoint) Equal(other *Outpoint) bool {
	return o.Txid.Equal(other.Txid) && o.Index == other.Index
}

// Bytes returns the outpoint as 36 bytes (32-byte txid + 4-byte little-endian index)
func (o *Outpoint) Bytes() []byte {
	return binary.LittleEndian.AppendUint32(o.Txid.CloneBytes(), o.Index)
}

// TxBytes is an alias for Bytes for backward compatibility
func (o *Outpoint) TxBytes() []byte {
	return o.Bytes()
}

// NewOutpointFromBytes creates a new Outpoint from a 36-byte slice
func NewOutpointFromBytes(b []byte) *Outpoint {
	if len(b) != 36 {
		return nil
	}
	o := &Outpoint{
		Index: binary.LittleEndian.Uint32(b[32:]),
	}
	copy(o.Txid[:], b[:32])
	return o
}

// OutpointFromString creates a new Outpoint from a string in the format "txid.outputIndex"
func OutpointFromString(s string) (*Outpoint, error) {
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
			o.Index = uint32(vout)
		}
	}
	return o, nil
}

// String returns the outpoint as a string in the format "txid.outputIndex"
func (o Outpoint) String() string {
	return fmt.Sprintf("%s.%d", o.Txid.String(), o.Index)
}

// OrdinalString returns the outpoint as a string in ordinal format "txid_outputIndex"
func (o *Outpoint) OrdinalString() string {
	return fmt.Sprintf("%s_%d", o.Txid.String(), o.Index)
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
	} else if op, err := OutpointFromString(x); err != nil {
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
		op := NewOutpointFromBytes(b)
		*o = *op
		return nil
	}
}
