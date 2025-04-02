package serializer

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
)

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

// Outpoint represents a transaction output reference (txid + output index)
type Outpoint string

// encodeOutpoints serializes a slice of outpoints
func encodeOutpoints(outpoints []string) ([]byte, error) {
	if outpoints == nil {
		return nil, nil
	}

	w := newWriter()
	w.writeVarInt(uint64(len(outpoints)))
	for _, op := range outpoints {
		opBytes, err := encodeOutpoint(op)
		if err != nil {
			return nil, err
		}
		w.writeBytes(opBytes)
	}
	return w.buf, nil
}

// decodeOutpoints deserializes a slice of outpoints
func decodeOutpoints(data []byte) ([]string, error) {
	if len(data) == 0 {
		return nil, nil
	}

	r := newReader(data)
	count, err := r.readVarInt()
	if err != nil {
		return nil, err
	}
	if count == math.MaxUint64 {
		return nil, nil
	}

	outpoints := make([]string, 0, count)
	for i := uint64(0); i < count; i++ {
		opBytes, err := r.readBytes(36)
		if err != nil {
			return nil, err
		}
		op, err := decodeOutpoint(opBytes)
		if err != nil {
			return nil, err
		}
		outpoints = append(outpoints, op)
	}
	return outpoints, nil
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
