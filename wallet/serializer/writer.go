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

func (w *writer) writeOptionalBytes(b []byte) {
	if b != nil {
		w.writeVarInt(uint64(len(b)))
		w.writeBytes(b)
	} else {
		w.writeVarInt(math.MaxUint64)
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
