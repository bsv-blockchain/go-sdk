package util

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"github.com/bsv-blockchain/go-sdk/chainhash"
)

// Reader is a helper for reading binary messages
type Reader struct {
	Data []byte
	Pos  int
}

func NewReader(data []byte) *Reader {
	return &Reader{Data: data}
}

func (r *Reader) IsComplete() bool {
	return r.Pos >= len(r.Data)
}

func (r *Reader) ReadByte() (byte, error) {
	if r.IsComplete() {
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
	if n < 0 {
		return nil, fmt.Errorf("invalid read length: %d", n)
	}
	b := r.Data[r.Pos : r.Pos+n]
	r.Pos += n
	return b, nil
}

func (r *Reader) ReadBytesReverse(n int) ([]byte, error) {
	b, err := r.ReadBytes(n)
	if err != nil {
		return nil, fmt.Errorf("error reading bytes reverse: %w", err)
	}
	// Reverse the byte slice
	var newBytes = make([]byte, len(b))
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		newBytes[i], newBytes[j] = b[j], b[i]
	}
	return newBytes, nil
}

func (r *Reader) ReadIntBytes() ([]byte, error) {
	linkageLen, err := r.ReadVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading bytes int length: %w", err)
	}
	if linkageLen <= 0 {
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

func (r *Reader) ReadVarIntOptional() (*uint64, error) {
	i, err := r.ReadVarInt()
	if err != nil {
		return nil, err
	}
	if i == math.MaxUint64 {
		return nil, nil
	}
	return &i, nil
}

func (r *Reader) ReadVarInt32() (uint32, error) {
	varUint64, err := r.ReadVarInt()
	return uint32(varUint64), err
}

// Read implements the io.Reader interface
func (r *Reader) Read(b []byte) (int, error) {
	if r.IsComplete() {
		return 0, errors.New("read past end of data")
	}
	n := copy(b, r.Data[r.Pos:])
	r.Pos += n
	return n, nil
}

func (r *Reader) ReadRemaining() []byte {
	if r.IsComplete() {
		return nil
	}
	pos := r.Pos
	r.Pos = len(r.Data)
	return r.Data[pos:]
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

func (r *Reader) ReadOptionalString(opts ...BytesOption) (string, error) {
	bytes, err := r.ReadOptionalBytes(opts...)
	if err != nil {
		return "", err
	}
	if bytes == nil {
		return "", nil
	}
	return string(bytes), nil
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
		length = chainhash.HashSize
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

func (r *Reader) ReadOptionalUint32() (*uint32, error) {
	val, err := r.ReadVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading val for optional uint32: %w", err)
	}
	if val == math.MaxUint64 {
		return nil, nil
	}
	var val32 uint32
	if val > math.MaxUint32 {
		return nil, fmt.Errorf("value %d exceeds uint32 maximum", val)
	}
	val32 = uint32(val)
	return &val32, nil
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

func (r *Reader) ReadTxidSlice() ([]chainhash.Hash, error) {
	count, err := r.ReadVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading slice txid count: %w", err)
	}
	if count == math.MaxUint64 {
		return nil, nil
	}

	txIDs := make([]chainhash.Hash, 0, count)
	for i := uint64(0); i < count; i++ {
		txIDBytes, err := r.ReadBytes(32)
		if err != nil {
			return nil, fmt.Errorf("error reading txIDBytes bytes for slice: %w", err)
		}
		txID, err := chainhash.NewHash(txIDBytes)
		if err != nil {
			return nil, fmt.Errorf("error creating chainhash from bytes for slice: %w", err)
		}

		txIDs = append(txIDs, *txID)
	}
	return txIDs, nil
}

func (r *Reader) ReadStringSlice() ([]string, error) {
	count, err := r.ReadVarInt()
	if err != nil {
		return nil, fmt.Errorf("error reading slice string count: %w", err)
	}
	if count == math.MaxUint64 {
		return nil, nil
	}
	if count >= math.MaxInt {
		return nil, fmt.Errorf("slice count %d exceeds maximum int size", count)
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

func (r *ReaderHoldError) IsComplete() bool {
	return r.Reader.IsComplete()
}

func (r *ReaderHoldError) CheckComplete() {
	if r.Err != nil {
		return
	}
	if !r.Reader.IsComplete() {
		r.Err = errors.New("finished reading but not all data consumed")
	}
}

func (r *ReaderHoldError) ReadVarInt() uint64 {
	if r.Err != nil {
		return 0
	}
	val, err := r.Reader.ReadVarInt()
	r.Err = err
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

func (r *ReaderHoldError) ReadOptionalUint32() *uint32 {
	if r.Err != nil {
		return nil
	}
	val, err := r.Reader.ReadOptionalUint32()
	r.Err = err
	return val
}

func (r *ReaderHoldError) ReadBytes(n int, errMsg ...string) []byte {
	if r.Err != nil {
		return nil
	}
	val, err := r.Reader.ReadBytes(n)
	r.Err = getErr(err, errMsg)
	return val
}

func (r *ReaderHoldError) ReadBytesReverse(n int) []byte {
	if r.Err != nil {
		return nil
	}
	val, err := r.Reader.ReadBytesReverse(n)
	r.Err = err
	return val
}

func (r *ReaderHoldError) ReadBase64Int() string {
	return r.ReadBase64(int(r.ReadVarInt()))
}

func (r *ReaderHoldError) ReadBase64(n int) string {
	return base64.StdEncoding.EncodeToString(r.ReadBytes(n))
}

func (r *ReaderHoldError) ReadHex(n int) string {
	return hex.EncodeToString(r.ReadBytes(n))
}

func (r *ReaderHoldError) ReadRemainingHex() string {
	return hex.EncodeToString(r.ReadRemaining())
}

func (r *ReaderHoldError) ReadIntBytes() []byte {
	if r.Err != nil {
		return nil
	}
	val, err := r.Reader.ReadIntBytes()
	r.Err = err
	return val
}

func (r *ReaderHoldError) ReadIntBytesHex() string {
	return hex.EncodeToString(r.ReadIntBytes())
}

// ReadByte returns the next byte and holds any error internally
func (r *ReaderHoldError) ReadByte() byte { //nolint:govet
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

func PtrToBool(opt *bool) bool {
	return opt != nil && *opt
}

// BoolPtr is a helper function to create a pointer to a boolean value
func BoolPtr(b bool) *bool {
	return &b
}

// Uint32Ptr is a helper function to create a pointer to a uint32 value
func Uint32Ptr(ui uint32) *uint32 {
	return &ui
}

func (r *ReaderHoldError) ReadTxidSlice() []chainhash.Hash {
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

func (r *ReaderHoldError) ReadString(errMsg ...string) string {
	if r.Err != nil {
		return ""
	}
	val, err := r.Reader.ReadString()
	r.Err = getErr(err, errMsg)
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

func getErr(err error, errMsg []string) error {
	if err == nil {
		return nil
	}
	if len(errMsg) == 0 {
		return err
	}
	return fmt.Errorf("%s: %w", errMsg[0], err)
}
