package util

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
)

// Reader is a helper for reading binary messages
type Reader struct {
	Data []byte
	Pos  int
}

func NewReader(data []byte) *Reader {
	return &Reader{Data: data}
}

func (r *Reader) ReadByte() (byte, error) {
	if r.Pos >= len(r.Data) {
		return 0, errors.New("read past end of data")
	}
	b := r.Data[r.Pos]
	r.Pos++
	return b, nil
}

func (r *Reader) ReadBytes(n int) ([]byte, error) {
	if r.Pos+n > len(r.Data) {
		return nil, errors.New("read past end of data")
	}
	b := r.Data[r.Pos : r.Pos+n]
	r.Pos += n
	return b, nil
}

func (r *Reader) ReadIntBytes() ([]byte, error) {
	linkageLen, err := r.ReadVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading bytes int length: %w", err)
	}
	if linkageLen == 0 {
		return nil, nil
	}
	b, err := r.ReadBytes(int(linkageLen))
	if err != nil {
		return nil, fmt.Errorf("error reading bytes int: %w", err)
	}
	return b, nil
}

func (r *Reader) ReadVarInt() (uint64, error) {
	var varInt VarInt
	if _, err := varInt.ReadFrom(r); err != nil {
		return 0, fmt.Errorf("error reading varint: %w", err)
	}
	return uint64(varInt), nil
}

func (r *Reader) ReadVarInt32() (uint32, error) {
	varUint64, err := r.ReadVarInt()
	return uint32(varUint64), err
}

// Read implements the io.Reader interface
func (r *Reader) Read(b []byte) (int, error) {
	if r.Pos >= len(r.Data) {
		return 0, errors.New("read past end of data")
	}
	n := copy(b, r.Data[r.Pos:])
	r.Pos += n
	return n, nil
}

func (r *Reader) ReadRemaining() []byte {
	if r.Pos >= len(r.Data) {
		return nil
	}
	return r.Data[r.Pos:]
}

func (r *Reader) ReadString() (string, error) {
	length, err := r.ReadVarInt()
	if err != nil {
		return "", fmt.Errorf("error reading string length: %w", err)
	}
	if length == math.MaxUint64 || length == 0 {
		return "", nil
	}
	data, err := r.ReadBytes(int(length))
	if err != nil {
		return "", fmt.Errorf("error reading string bytes: %w", err)
	}
	return string(data), nil
}

func (r *Reader) ReadOptionalBytes(opts ...BytesOption) ([]byte, error) {
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
		txFlag, err := r.ReadByte()
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
		length, err = r.ReadVarInt()
		if err != nil {
			return nil, fmt.Errorf("error reading length: %w", err)
		}
	}
	if length == math.MaxUint64 || length == 0 {
		return nil, nil
	}
	return r.ReadBytes(int(length))
}

func (r *Reader) ReadOptionalUint32() (uint32, error) {
	val, err := r.ReadVarInt()
	if err != nil {
		return 0, fmt.Errorf("error reading val for optional uint32: %w", err)
	}
	if val == math.MaxUint64 {
		return 0, nil
	}
	return uint32(val), nil
}

func (r *Reader) ReadOptionalBool() (*bool, error) {
	b, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("error reading byte for optional bool: %w", err)
	}
	if b == 0xFF {
		return nil, nil
	}
	val := b == 1
	return &val, nil
}

func (r *Reader) ReadTxidSlice() ([]string, error) {
	count, err := r.ReadVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading slice txid count: %w", err)
	}
	if count == math.MaxUint64 {
		return nil, nil
	}

	txids := make([]string, 0, count)
	for i := uint64(0); i < count; i++ {
		txid, err := r.ReadBytes(32)
		if err != nil {
			return nil, fmt.Errorf("error reading txid bytes for slice: %w", err)
		}
		txids = append(txids, hex.EncodeToString(txid))
	}
	return txids, nil
}

func (r *Reader) ReadStringSlice() ([]string, error) {
	count, err := r.ReadVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading slice string count: %w", err)
	}
	if count == math.MaxUint64 {
		return nil, nil
	}

	slice := make([]string, 0, count)
	for i := uint64(0); i < count; i++ {
		str, err := r.ReadString()
		if err != nil {
			return nil, fmt.Errorf("error reading string for slice: %w", err)
		}
		slice = append(slice, str)
	}
	return slice, nil
}

func (r *Reader) ReadOptionalToHex() (string, error) {
	dataLen, err := r.ReadVarInt()
	if err != nil {
		return "", fmt.Errorf("error reading data length for optional hex: %w", err)
	}
	if dataLen == math.MaxUint64 {
		return "", nil
	}
	data, err := r.ReadBytes(int(dataLen))
	if err != nil {
		return "", fmt.Errorf("error reading data bytes for optional hex: %w", err)
	}
	return hex.EncodeToString(data), nil
}

type ReaderHoldError struct {
	Err    error
	Reader Reader
}

func NewReaderHoldError(data []byte) *ReaderHoldError {
	return &ReaderHoldError{
		Reader: Reader{Data: data},
	}
}

func (r *ReaderHoldError) ReadVarInt() uint64 {
	var val uint64
	if r.Err == nil {
		val, r.Err = r.Reader.ReadVarInt()
	}
	if r.Err != nil {
		return 0
	}
	return val
}

func (r *ReaderHoldError) ReadVarInt32() uint32 {
	if r.Err != nil {
		return 0
	}
	val, err := r.Reader.ReadVarInt32()
	r.Err = err
	return val
}

func (r *ReaderHoldError) ReadOptionalUint32() uint32 {
	if r.Err != nil {
		return 0
	}
	val, err := r.Reader.ReadOptionalUint32()
	r.Err = err
	return val
}

func (r *ReaderHoldError) ReadBytes(n int) []byte {
	if r.Err != nil {
		return nil
	}
	val, err := r.Reader.ReadBytes(n)
	r.Err = err
	return val
}

func (r *ReaderHoldError) ReadIntBytes() []byte {
	if r.Err != nil {
		return nil
	}
	val, err := r.Reader.ReadIntBytes()
	r.Err = err
	return val
}

func (r *ReaderHoldError) ReadByte() byte {
	if r.Err != nil {
		return 0
	}
	val, err := r.Reader.ReadByte()
	r.Err = err
	return val
}

func (r *ReaderHoldError) ReadOptionalBool() *bool {
	if r.Err != nil {
		return nil
	}
	val, err := r.Reader.ReadOptionalBool()
	r.Err = err
	return val
}

func ReadOptionalBoolAsBool(opt *bool) bool {
	return opt != nil && *opt
}

// BoolPtr is a helper function to create a pointer to a boolean value
func BoolPtr(b bool) *bool {
	return &b
}

func (r *ReaderHoldError) ReadTxidSlice() []string {
	if r.Err != nil {
		return nil
	}
	val, err := r.Reader.ReadTxidSlice()
	r.Err = err
	return val
}

func (r *ReaderHoldError) ReadOptionalBytes(opts ...BytesOption) []byte {
	if r.Err != nil {
		return nil
	}
	val, err := r.Reader.ReadOptionalBytes(opts...)
	r.Err = err
	return val
}

func (r *ReaderHoldError) ReadString() string {
	if r.Err != nil {
		return ""
	}
	val, err := r.Reader.ReadString()
	r.Err = err
	return val
}

func (r *ReaderHoldError) ReadStringSlice() []string {
	if r.Err != nil {
		return nil
	}
	val, err := r.Reader.ReadStringSlice()
	r.Err = err
	return val
}

func (r *ReaderHoldError) ReadOptionalToHex() string {
	if r.Err != nil {
		return ""
	}
	val, err := r.Reader.ReadOptionalToHex()
	r.Err = err
	return val
}

func (r *ReaderHoldError) ReadRemaining() []byte {
	if r.Err != nil {
		return nil
	}
	return r.Reader.ReadRemaining()
}
