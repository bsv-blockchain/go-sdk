package util

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"math"
	"sort"
)

// Writer is a helper for building binary messages
type Writer struct {
	Buf []byte
}

func NewWriter() *Writer {
	return &Writer{}
}

//nolint:govet // suppress WriteByte signature mismatch
func (w *Writer) WriteByte(b byte) {
	w.Buf = append(w.Buf, b)
}

func (w *Writer) WriteBytes(b []byte) {
	w.Buf = append(w.Buf, b...)
}

func (w *Writer) WriteBytesReverse(b []byte) {
	// Reverse the byte slice before appending
	var newBytes = make([]byte, len(b))
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		newBytes[i], newBytes[j] = b[j], b[i]
	}
	w.WriteBytes(newBytes)
}

func (w *Writer) WriteIntBytes(b []byte) {
	w.WriteVarInt(uint64(len(b)))
	w.WriteBytes(b)
}

func (w *Writer) WriteIntBytesOptional(b []byte) {
	if len(b) == 0 {
		w.WriteNegativeOne()
	} else {
		w.WriteIntBytes(b)
	}
}

func (w *Writer) WriteVarInt(n uint64) {
	w.WriteBytes(VarInt(n).Bytes())
}

func (w *Writer) WriteVarIntOptional(n *uint64) {
	if n == nil {
		w.WriteNegativeOne()
		return
	}
	w.WriteBytes(VarInt(*n).Bytes())
}

const (
	NegativeOne     = math.MaxUint64
	NegativeOneByte = 0xFF
)

func (w *Writer) WriteNegativeOne() {
	w.WriteVarInt(NegativeOne) // 0xFFFFFFFFFFFFFFFFFF (9x 0xFF)
}

func (w *Writer) WriteNegativeOneByte() {
	w.WriteByte(NegativeOneByte)
}

func IsNegativeOne(val uint64) bool {
	return val == NegativeOne
}

func IsNegativeOneByte(b byte) bool {
	return b == NegativeOneByte
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
		w.WriteNegativeOne()
	}
}

func (w *Writer) WriteOptionalFromHex(s string) error {
	if s != "" {
		return w.WriteIntFromHex(s)
	} else {
		w.WriteNegativeOne()
	}
	return nil
}

func (w *Writer) WriteRemainingFromHex(s string) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("error write invalid hex: %w", err)
	}
	w.WriteBytes(b)
	return nil
}

func (w *Writer) WriteIntFromHex(s string) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("error write invalid hex: %w", err)
	}
	w.WriteIntBytes(b)
	return nil
}

func (w *Writer) WriteSizeFromHex(s string, size int) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("invalid certifier hex: %w", err)
	}
	if len(b) != size {
		return fmt.Errorf("hex must be %d bytes long, got %d", size, len(b))
	}
	w.WriteBytes(b)
	return nil
}

func (w *Writer) WriteIntFromBase64(s string) error {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("error write invalid base64: %w", err)
	}
	w.WriteIntBytes(b)
	return nil
}

func (w *Writer) WriteSizeFromBase64(s string, size int) error {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("invalid certifier base64: %w", err)
	}
	if len(b) != size {
		return fmt.Errorf("base64 must be %d bytes long, got %d", size, len(b))
	}
	w.WriteBytes(b)
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

func (w *Writer) WriteOptionalUint32(n *uint32) {
	if n != nil {
		w.WriteVarInt(uint64(*n))
	} else {
		w.WriteNegativeOne()
	}
}

func (w *Writer) WriteStringSlice(slice []string) {
	if slice != nil {
		w.WriteVarInt(uint64(len(slice)))
		for _, s := range slice {
			w.WriteOptionalString(s)
		}
	} else {
		w.WriteNegativeOne()
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
		w.WriteNegativeOneByte()
	}
}

func (w *Writer) WriteTxidSlice(txIDs []chainhash.Hash) error {
	if txIDs != nil {
		w.WriteVarInt(uint64(len(txIDs)))
		for _, txID := range txIDs {
			w.WriteBytes(txID[:])
		}
	} else {
		w.WriteVarInt(math.MaxUint64) // -1
	}
	return nil
}

func (w *Writer) WriteStringMap(stringMap map[string]string) {
	keys := make([]string, 0, len(stringMap))
	for k := range stringMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	w.WriteVarInt(uint64(len(keys)))
	for _, key := range keys {
		w.WriteString(key)
		w.WriteString(stringMap[key])
	}
}
