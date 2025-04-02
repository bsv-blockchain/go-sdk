package serializer

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"math"
)

// reader is a helper for reading binary messages
type reader struct {
	data []byte
	pos  int
}

func newReader(data []byte) *reader {
	return &reader{data: data}
}

func (r *reader) readByte() (byte, error) {
	if r.pos >= len(r.data) {
		return 0, errors.New("read past end of data")
	}
	b := r.data[r.pos]
	r.pos++
	return b, nil
}

func (r *reader) readBytes(n int) ([]byte, error) {
	if r.pos+n > len(r.data) {
		return nil, errors.New("read past end of data")
	}
	b := r.data[r.pos : r.pos+n]
	r.pos += n
	return b, nil
}

func (r *reader) readVarInt() (uint64, error) {
	var varInt transaction.VarInt
	if _, err := varInt.ReadFrom(r); err != nil {
		return 0, fmt.Errorf("error reading varint: %w", err)
	}
	return uint64(varInt), nil
}

func (r *reader) readVarInt32() (uint32, error) {
	varUint64, err := r.readVarInt()
	return uint32(varUint64), err
}

// ReadByte implements the io.ByteReader interface
func (r *reader) ReadByte() (byte, error) {
	return r.readByte()
}

// Read implements the io.Reader interface
func (r *reader) Read(b []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, errors.New("read past end of data")
	}
	n := copy(b, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *reader) readRemaining() []byte {
	if r.pos >= len(r.data) {
		return nil
	}
	return r.data[r.pos:]
}

func (r *reader) readString() (string, error) {
	length, err := r.readVarInt()
	if err != nil {
		return "", fmt.Errorf("error reading string length: %w", err)
	}
	if length == math.MaxUint64 || length == 0 {
		return "", nil
	}
	data, err := r.readBytes(int(length))
	if err != nil {
		return "", fmt.Errorf("error reading string bytes: %w", err)
	}
	return string(data), nil
}

func (r *reader) readOptionalBytes(opts ...BytesOption) ([]byte, error) {
	var withFlag, txIdLen bool
	for _, opt := range opts {
		switch opt {
		case BytesOptionWithFlag:
			withFlag = true
		case BytesOptionTxIdLen:
			txIdLen = true
		}
	}
	if withFlag {
		txFlag, err := r.readByte()
		if err != nil {
			return nil, fmt.Errorf("error reading tx flag: %w", err)
		}
		if txFlag != 1 {
			return nil, nil
		}
	}
	var length uint64
	if txIdLen {
		length = 32
	} else {
		var err error
		length, err = r.readVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading length: %w", err)
		}
	}
	if length == math.MaxUint64 || length == 0 {
		return nil, nil
	}
	return r.readBytes(int(length))
}

func (r *reader) readOptionalUint32() (uint32, error) {
	val, err := r.readVarInt()
	if err != nil {
		return 0, err
	}
	if val == math.MaxUint64 {
		return 0, nil
	}
	return uint32(val), nil
}

func (r *reader) readOptionalBool() (*bool, error) {
	b, err := r.readByte()
	if err != nil {
		return nil, err
	}
	if b == 0xFF {
		return nil, nil
	}
	val := b == 1
	return &val, nil
}

func (r *reader) readTxidSlice() ([]string, error) {
	count, err := r.readVarInt()
	if err != nil {
		return nil, err
	}
	if count == math.MaxUint64 {
		return nil, nil
	}

	txids := make([]string, 0, count)
	for i := uint64(0); i < count; i++ {
		txid, err := r.readBytes(32)
		if err != nil {
			return nil, err
		}
		txids = append(txids, hex.EncodeToString(txid))
	}
	return txids, nil
}

func (r *reader) readStringSlice() ([]string, error) {
	count, err := r.readVarInt()
	if err != nil {
		return nil, err
	}
	if count == math.MaxUint64 {
		return nil, nil
	}

	slice := make([]string, 0, count)
	for i := uint64(0); i < count; i++ {
		str, err := r.readString()
		if err != nil {
			return nil, err
		}
		slice = append(slice, str)
	}
	return slice, nil
}
