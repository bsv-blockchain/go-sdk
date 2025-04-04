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
		return 0, fmt.Errorf("error reading val for optional uint32: %w", err)
	}
	if val == math.MaxUint64 {
		return 0, nil
	}
	return uint32(val), nil
}

func (r *reader) readOptionalBool() (*bool, error) {
	b, err := r.readByte()
	if err != nil {
		return nil, fmt.Errorf("error reading byte for optional bool: %w", err)
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
		return nil, fmt.Errorf("error reading slice txid count: %w", err)
	}
	if count == math.MaxUint64 {
		return nil, nil
	}

	txids := make([]string, 0, count)
	for i := uint64(0); i < count; i++ {
		txid, err := r.readBytes(32)
		if err != nil {
			return nil, fmt.Errorf("error reading txid bytes for slice: %w", err)
		}
		txids = append(txids, hex.EncodeToString(txid))
	}
	return txids, nil
}

func (r *reader) readStringSlice() ([]string, error) {
	count, err := r.readVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading slice string count: %w", err)
	}
	if count == math.MaxUint64 {
		return nil, nil
	}

	slice := make([]string, 0, count)
	for i := uint64(0); i < count; i++ {
		str, err := r.readString()
		if err != nil {
			return nil, fmt.Errorf("error reading string for slice: %w", err)
		}
		slice = append(slice, str)
	}
	return slice, nil
}

func (r *reader) readOptionalToHex() (string, error) {
	dataLen, err := r.readVarInt()
	if err != nil {
		return "", fmt.Errorf("error reading data length for optional hex: %w", err)
	}
	if dataLen == math.MaxUint64 {
		return "", nil
	}
	data, err := r.readBytes(int(dataLen))
	if err != nil {
		return "", fmt.Errorf("error reading data bytes for optional hex: %w", err)
	}
	return hex.EncodeToString(data), nil
}

type readerHoldError struct {
	err    error
	reader reader
}

func newReaderHoldError(data []byte) *readerHoldError {
	return &readerHoldError{
		reader: reader{data: data},
	}
}

func (r *readerHoldError) readVarInt() uint64 {
	var val uint64
	if r.err == nil {
		val, r.err = r.reader.readVarInt()
	}
	if r.err != nil {
		return 0
	}
	return val
}

func (r *readerHoldError) readVarInt32() uint32 {
	if r.err != nil {
		return 0
	}
	val, err := r.reader.readVarInt32()
	r.err = err
	return val
}

func (r *readerHoldError) readOptionalUint32() uint32 {
	if r.err != nil {
		return 0
	}
	val, err := r.reader.readOptionalUint32()
	r.err = err
	return val
}

func (r *readerHoldError) readBytes(n int) []byte {
	if r.err != nil {
		return nil
	}
	val, err := r.reader.readBytes(n)
	r.err = err
	return val
}

func (r *readerHoldError) readByte() byte {
	if r.err != nil {
		return 0
	}
	val, err := r.reader.readByte()
	r.err = err
	return val
}

func (r *readerHoldError) readOptionalBool() *bool {
	if r.err != nil {
		return nil
	}
	val, err := r.reader.readOptionalBool()
	r.err = err
	return val
}

func readOptionalBoolAsBool(opt *bool) bool {
	return opt != nil && *opt
}

func (r *readerHoldError) readTxidSlice() []string {
	if r.err != nil {
		return nil
	}
	val, err := r.reader.readTxidSlice()
	r.err = err
	return val
}

func (r *readerHoldError) readOptionalBytes(opts ...BytesOption) []byte {
	if r.err != nil {
		return nil
	}
	val, err := r.reader.readOptionalBytes(opts...)
	r.err = err
	return val
}

func (r *readerHoldError) readString() string {
	if r.err != nil {
		return ""
	}
	val, err := r.reader.readString()
	r.err = err
	return val
}

func (r *readerHoldError) readStringSlice() []string {
	if r.err != nil {
		return nil
	}
	val, err := r.reader.readStringSlice()
	r.err = err
	return val
}

func (r *readerHoldError) readOptionalToHex() string {
	if r.err != nil {
		return ""
	}
	val, err := r.reader.readOptionalToHex()
	r.err = err
	return val
}

func (r *readerHoldError) readRemaining() []byte {
	if r.err != nil {
		return nil
	}
	return r.reader.readRemaining()
}
