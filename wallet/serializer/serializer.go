package serializer

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"strings"
)

// writer is a helper for building binary messages
type writer struct {
	buf []byte
}

func newWriter() *writer {
	return &writer{}
}

func (w *writer) writeByte(b byte) {
	w.buf = append(w.buf, b)
}

func (w *writer) writeBytes(b []byte) {
	w.buf = append(w.buf, b...)
}

func (w *writer) writeVarInt(n uint64) {
	w.writeBytes(transaction.VarInt(n).Bytes())
}

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

// encodeOutpoint converts outpoint string "txid.index" to binary format
func encodeOutpoint(outpoint string) ([]byte, error) {
	parts := strings.Split(outpoint, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid outpoint format")
	}

	txid, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid txid: %w", err)
	}

	var index uint32
	if _, err := fmt.Sscanf(parts[1], "%d", &index); err != nil {
		return nil, fmt.Errorf("invalid index: %w", err)
	}

	buf := make([]byte, 36)
	copy(buf[:32], txid)
	binary.BigEndian.PutUint32(buf[32:36], index)

	return buf, nil
}

// decodeOutpoint converts binary outpoint data to string format "txid.index"
func decodeOutpoint(data []byte) (string, error) {
	if len(data) < 32 {
		return "", errors.New("invalid outpoint data length")
	}

	txid := hex.EncodeToString(data[:32])
	index := binary.BigEndian.Uint32(data[32:36])
	return fmt.Sprintf("%s.%d", txid, index), nil
}

func boolPtr(b bool) *bool {
	return &b
}
