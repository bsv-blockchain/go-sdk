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
