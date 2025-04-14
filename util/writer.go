package util

import (
	"encoding/hex"
	"fmt"
	"math"
)

// Writer is a helper for building binary messages
type Writer struct {
	Buf []byte
}

func NewWriter() *Writer {
	return &Writer{}
}

func (w *Writer) WriteByte(b byte) {
	w.Buf = append(w.Buf, b)
}

func (w *Writer) WriteBytes(b []byte) {
	w.Buf = append(w.Buf, b...)
}

func (w *Writer) WriteIntBytes(b []byte) {
	w.WriteVarInt(uint64(len(b)))
	w.WriteBytes(b)
}

func (w *Writer) WriteVarInt(n uint64) {
	w.WriteBytes(VarInt(n).Bytes())
}

func (w *Writer) WriteString(s string) {
	b := []byte(s)
	w.WriteVarInt(uint64(len(b)))
	w.WriteBytes(b)
}

func (w *Writer) WriteOptionalString(s string) {
	if s != "" {
		b := []byte(s)
		w.WriteVarInt(uint64(len(b)))
		w.WriteBytes(b)
	} else {
		w.WriteVarInt(math.MaxUint64)
	}
}

func (w *Writer) WriteOptionalFromHex(s string) error {
	if s != "" {
		b, err := hex.DecodeString(s)
		if err != nil {
			return fmt.Errorf("error write invalid hex: %w", err)
		}
		w.WriteVarInt(uint64(len(b)))
		w.WriteBytes(b)
	} else {
		w.WriteVarInt(math.MaxUint64)
	}
	return nil
}

type BytesOption int

const (
	BytesOptionWithFlag    BytesOption = 1
	BytesOptionTxIdLen     BytesOption = 2
	BytesOptionZeroIfEmpty BytesOption = 3
)

func (w *Writer) WriteOptionalBytes(b []byte, options ...BytesOption) {
	var withFlag, txIdLen, zeroIfEmpty bool
	for _, opt := range options {
		switch opt {
		case BytesOptionWithFlag:
			withFlag = true
		case BytesOptionTxIdLen:
			txIdLen = true
		case BytesOptionZeroIfEmpty:
			zeroIfEmpty = true
		}
	}
	hasData := len(b) > 0
	if withFlag {
		if hasData {
			w.WriteByte(1)
		} else {
			w.WriteByte(0)
			return
		}
	}
	if hasData {
		if !txIdLen {
			w.WriteVarInt(uint64(len(b)))
		}
		w.WriteBytes(b)
	} else {
		if zeroIfEmpty {
			w.WriteVarInt(0)
		} else {
			w.WriteVarInt(math.MaxUint64)
		}
	}
}

func (w *Writer) WriteOptionalUint32(n uint32) {
	if n > 0 {
		w.WriteVarInt(uint64(n))
	} else {
		w.WriteVarInt(math.MaxUint64)
	}
}

func (w *Writer) WriteStringSlice(slice []string) {
	if slice != nil {
		w.WriteVarInt(uint64(len(slice)))
		for _, s := range slice {
			w.WriteOptionalString(s)
		}
	} else {
		w.WriteVarInt(math.MaxUint64)
	}
}

func (w *Writer) WriteOptionalBool(b *bool) {
	if b != nil {
		if *b {
			w.WriteByte(1)
		} else {
			w.WriteByte(0)
		}
	} else {
		w.WriteByte(0xFF) // -1
	}
}

func (w *Writer) WriteTxidSlice(txids []string) error {
	if txids != nil {
		w.WriteVarInt(uint64(len(txids)))
		for _, txid := range txids {
			txidBytes, err := hex.DecodeString(txid)
			if err != nil {
				return fmt.Errorf("error decoding txid: %w", err)
			}
			w.WriteBytes(txidBytes)
		}
	} else {
		w.WriteVarInt(math.MaxUint64) // -1
	}
	return nil
}

// package util

// import (
// 	"encoding/binary"
// 	"errors"
// )

// // Writer is a helper for building binary messages
// type Writer struct {
// 	buf []byte
// }

// // NewWriter creates a new Writer instance
// func NewWriter() *Writer {
// 	return &Writer{buf: make([]byte, 0, 512)}
// }

// // WriteByte appends a single byte to the buffer
// func (w *Writer) WriteByte(b byte) {
// 	w.buf = append(w.buf, b)
// }

// // WriteBytes appends multiple bytes to the buffer
// func (w *Writer) WriteBytes(b []byte) {
// 	w.buf = append(w.buf, b...)
// }

// // WriteVarInt writes a variable-length integer to the buffer
// func (w *Writer) WriteVarInt(n uint64) {
// 	if n < 0xfd {
// 		w.WriteByte(byte(n))
// 	} else if n <= 0xffff {
// 		w.WriteByte(0xfd)
// 		buf := make([]byte, 2)
// 		binary.LittleEndian.PutUint16(buf, uint16(n))
// 		w.WriteBytes(buf)
// 	} else if n <= 0xffffffff {
// 		w.WriteByte(0xfe)
// 		buf := make([]byte, 4)
// 		binary.LittleEndian.PutUint32(buf, uint32(n))
// 		w.WriteBytes(buf)
// 	} else {
// 		w.WriteByte(0xff)
// 		buf := make([]byte, 8)
// 		binary.LittleEndian.PutUint64(buf, n)
// 		w.WriteBytes(buf)
// 	}
// }

// // WriteUInt16BE writes an unsigned 16-bit integer in big-endian format
// func (w *Writer) WriteUInt16BE(n uint16) {
// 	buf := make([]byte, 2)
// 	binary.BigEndian.PutUint16(buf, n)
// 	w.WriteBytes(buf)
// }

// // WriteUInt16LE writes an unsigned 16-bit integer in little-endian format
// func (w *Writer) WriteUInt16LE(n uint16) {
// 	buf := make([]byte, 2)
// 	binary.LittleEndian.PutUint16(buf, n)
// 	w.WriteBytes(buf)
// }

// // WriteUInt32BE writes an unsigned 32-bit integer in big-endian format
// func (w *Writer) WriteUInt32BE(n uint32) {
// 	buf := make([]byte, 4)
// 	binary.BigEndian.PutUint32(buf, n)
// 	w.WriteBytes(buf)
// }

// // WriteUInt32LE writes an unsigned 32-bit integer in little-endian format
// func (w *Writer) WriteUInt32LE(n uint32) {
// 	buf := make([]byte, 4)
// 	binary.LittleEndian.PutUint32(buf, n)
// 	w.WriteBytes(buf)
// }

// // WriteUInt64BE writes an unsigned 64-bit integer in big-endian format
// func (w *Writer) WriteUInt64BE(n uint64) {
// 	buf := make([]byte, 8)
// 	binary.BigEndian.PutUint64(buf, n)
// 	w.WriteBytes(buf)
// }

// // WriteUInt64LE writes an unsigned 64-bit integer in little-endian format
// func (w *Writer) WriteUInt64LE(n uint64) {
// 	buf := make([]byte, 8)
// 	binary.LittleEndian.PutUint64(buf, n)
// 	w.WriteBytes(buf)
// }

// // Bytes returns the underlying buffer
// func (w *Writer) Bytes() []byte {
// 	return w.buf
// }

// // Reader is a helper for reading binary messages
// type Reader struct {
// 	data []byte
// 	pos  int
// }

// // NewReader creates a new Reader instance
// func NewReader(data []byte) *Reader {
// 	return &Reader{data: data, pos: 0}
// }

// // EOF returns true if the reader position is at the end of the data
// func (r *Reader) EOF() bool {
// 	return r.pos >= len(r.data)
// }

// // ReadByte reads and returns a single byte
// func (r *Reader) ReadByte() (byte, error) {
// 	if r.pos >= len(r.data) {
// 		return 0, errors.New("read past end of data")
// 	}
// 	b := r.data[r.pos]
// 	r.pos++
// 	return b, nil
// }

// // ReadBytes reads n bytes from the buffer
// func (r *Reader) ReadBytes(n int) ([]byte, error) {
// 	if r.pos+n > len(r.data) {
// 		return nil, errors.New("read past end of data")
// 	}
// 	b := r.data[r.pos : r.pos+n]
// 	r.pos += n
// 	return b, nil
// }

// // ReadVarInt reads a variable-length integer
// func (r *Reader) ReadVarInt() (uint64, error) {
// 	if r.pos >= len(r.data) {
// 		return 0, errors.New("read past end of data")
// 	}

// 	prefix := r.data[r.pos]
// 	r.pos++

// 	switch prefix {
// 	case 0xfd:
// 		if r.pos+2 > len(r.data) {
// 			return 0, errors.New("read past end of data")
// 		}
// 		val := binary.LittleEndian.Uint16(r.data[r.pos : r.pos+2])
// 		r.pos += 2
// 		return uint64(val), nil
// 	case 0xfe:
// 		if r.pos+4 > len(r.data) {
// 			return 0, errors.New("read past end of data")
// 		}
// 		val := binary.LittleEndian.Uint32(r.data[r.pos : r.pos+4])
// 		r.pos += 4
// 		return uint64(val), nil
// 	case 0xff:
// 		if r.pos+8 > len(r.data) {
// 			return 0, errors.New("read past end of data")
// 		}
// 		val := binary.LittleEndian.Uint64(r.data[r.pos : r.pos+8])
// 		r.pos += 8
// 		return val, nil
// 	default:
// 		return uint64(prefix), nil
// 	}
// }

// // ReadUInt16BE reads an unsigned 16-bit integer in big-endian format
// func (r *Reader) ReadUInt16BE() (uint16, error) {
// 	if r.pos+2 > len(r.data) {
// 		return 0, errors.New("read past end of data")
// 	}
// 	val := binary.BigEndian.Uint16(r.data[r.pos : r.pos+2])
// 	r.pos += 2
// 	return val, nil
// }

// // ReadUInt16LE reads an unsigned 16-bit integer in little-endian format
// func (r *Reader) ReadUInt16LE() (uint16, error) {
// 	if r.pos+2 > len(r.data) {
// 		return 0, errors.New("read past end of data")
// 	}
// 	val := binary.LittleEndian.Uint16(r.data[r.pos : r.pos+2])
// 	r.pos += 2
// 	return val, nil
// }

// // ReadUInt32BE reads an unsigned 32-bit integer in big-endian format
// func (r *Reader) ReadUInt32BE() (uint32, error) {
// 	if r.pos+4 > len(r.data) {
// 		return 0, errors.New("read past end of data")
// 	}
// 	val := binary.BigEndian.Uint32(r.data[r.pos : r.pos+4])
// 	r.pos += 4
// 	return val, nil
// }

// // ReadUInt32LE reads an unsigned 32-bit integer in little-endian format
// func (r *Reader) ReadUInt32LE() (uint32, error) {
// 	if r.pos+4 > len(r.data) {
// 		return 0, errors.New("read past end of data")
// 	}
// 	val := binary.LittleEndian.Uint32(r.data[r.pos : r.pos+4])
// 	r.pos += 4
// 	return val, nil
// }

// // ReadUInt64BE reads an unsigned 64-bit integer in big-endian format
// func (r *Reader) ReadUInt64BE() (uint64, error) {
// 	if r.pos+8 > len(r.data) {
// 		return 0, errors.New("read past end of data")
// 	}
// 	val := binary.BigEndian.Uint64(r.data[r.pos : r.pos+8])
// 	r.pos += 8
// 	return val, nil
// }

// // ReadUInt64LE reads an unsigned 64-bit integer in little-endian format
// func (r *Reader) ReadUInt64LE() (uint64, error) {
// 	if r.pos+8 > len(r.data) {
// 		return 0, errors.New("read past end of data")
// 	}
// 	val := binary.LittleEndian.Uint64(r.data[r.pos : r.pos+8])
// 	r.pos += 8
// 	return val, nil
// }

// // Position returns the current position in the buffer
// func (r *Reader) Position() int {
// 	return r.pos
// }

// // Remaining returns the number of bytes left to read
// func (r *Reader) Remaining() int {
// 	return len(r.data) - r.pos
// }

// // Read reads all remaining bytes if n is 0, or n bytes otherwise
// func (r *Reader) Read(n ...int) ([]byte, error) {
// 	length := r.Remaining()
// 	if len(n) > 0 && n[0] > 0 {
// 		length = n[0]
// 	}
// 	return r.ReadBytes(length)
// }
