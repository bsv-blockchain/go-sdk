package serializer

import (
	"encoding/hex"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"math"
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

func (w *writer) writeString(s string) {
	b := []byte(s)
	w.writeVarInt(uint64(len(b)))
	w.writeBytes(b)
}

func (w *writer) writeOptionalString(s string) {
	if s != "" {
		b := []byte(s)
		w.writeVarInt(uint64(len(b)))
		w.writeBytes(b)
	} else {
		w.writeVarInt(math.MaxUint64)
	}
}

func (w *writer) writeOptionalFromHex(s string) error {
	if s != "" {
		b, err := hex.DecodeString(s)
		if err != nil {
			return fmt.Errorf("error write invalid hex: %w", err)
		}
		w.writeVarInt(uint64(len(b)))
		w.writeBytes(b)
	} else {
		w.writeVarInt(math.MaxUint64)
	}
	return nil
}

type BytesOption int

const (
	BytesOptionWithFlag    BytesOption = 1
	BytesOptionTxIdLen     BytesOption = 2
	BytesOptionZeroIfEmpty BytesOption = 3
)

func (w *writer) writeOptionalBytes(b []byte, options ...BytesOption) {
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
			w.writeByte(1)
		} else {
			w.writeByte(0)
			return
		}
	}
	if hasData {
		if !txIdLen {
			w.writeVarInt(uint64(len(b)))
		}
		w.writeBytes(b)
	} else {
		if zeroIfEmpty {
			w.writeVarInt(0)
		} else {
			w.writeVarInt(math.MaxUint64)
		}
	}
}

func (w *writer) writeOptionalUint32(n uint32) {
	if n > 0 {
		w.writeVarInt(uint64(n))
	} else {
		w.writeVarInt(math.MaxUint64)
	}
}

func (w *writer) writeStringSlice(slice []string) {
	if slice != nil {
		w.writeVarInt(uint64(len(slice)))
		for _, s := range slice {
			w.writeOptionalString(s)
		}
	} else {
		w.writeVarInt(math.MaxUint64)
	}
}

func (w *writer) writeOptionalBool(b *bool) {
	if b != nil {
		if *b {
			w.writeByte(1)
		} else {
			w.writeByte(0)
		}
	} else {
		w.writeByte(0xFF) // -1
	}
}

func (w *writer) writeTxidSlice(txids []string) error {
	if txids != nil {
		w.writeVarInt(uint64(len(txids)))
		for _, txid := range txids {
			txidBytes, err := hex.DecodeString(txid)
			if err != nil {
				return fmt.Errorf("error decoding txid: %w", err)
			}
			w.writeBytes(txidBytes)
		}
	} else {
		w.writeVarInt(math.MaxUint64) // -1
	}
	return nil
}
