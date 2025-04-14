package serializer

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"math"
	"strings"
)

const OutpointSize = 36

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

	buf := make([]byte, OutpointSize)
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
		opBytes, err := r.readBytes(OutpointSize)
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
	if len(data) != OutpointSize {
		return "", errors.New("invalid outpoint data length")
	}

	txid := hex.EncodeToString(data[:32])
	index := binary.BigEndian.Uint32(data[32:36])
	return fmt.Sprintf("%s.%d", txid, index), nil
}

// encodeCounterparty writes counterparty in the same format as TypeScript version
func encodeCounterparty(w *writer, counterparty wallet.Counterparty) error {
	switch counterparty.Type {
	case wallet.CounterpartyUninitialized:
		w.writeByte(0)
	case wallet.CounterpartyTypeSelf:
		w.writeByte(11)
	case wallet.CounterpartyTypeAnyone:
		w.writeByte(12)
	case wallet.CounterpartyTypeOther:
		if counterparty.Counterparty == nil {
			return errors.New("counterparty is nil for type other")
		}
		w.writeBytes(counterparty.Counterparty.ToDER())
	default:
		return fmt.Errorf("unknown counterparty type: %v", counterparty.Type)
	}
	return nil
}

// decodeCounterparty reads counterparty in the same format as TypeScript version
func decodeCounterparty(r *readerHoldError) (wallet.Counterparty, error) {
	counterparty := wallet.Counterparty{}
	counterpartyFlag := r.readByte()
	switch counterpartyFlag {
	case 0:
		counterparty.Type = wallet.CounterpartyUninitialized
	case 11:
		counterparty.Type = wallet.CounterpartyTypeSelf
	case 12:
		counterparty.Type = wallet.CounterpartyTypeAnyone
	default:
		pubKey, err := ec.PublicKeyFromBytes(append([]byte{counterpartyFlag}, r.readBytes(32)...))
		if err != nil {
			return counterparty, fmt.Errorf("invalid counterparty bytes: %w", err)
		}
		counterparty.Type = wallet.CounterpartyTypeOther
		counterparty.Counterparty = pubKey
	}
	return counterparty, nil
}

// KeyRelatedParams contains protocol, key and privilege parameters
type KeyRelatedParams struct {
	ProtocolID       wallet.Protocol
	KeyID            string
	Counterparty     wallet.Counterparty
	Privileged       *bool
	PrivilegedReason string
}

// encodeProtocol serializes a Protocol to bytes matching the TypeScript format
func encodeProtocol(protocol wallet.Protocol) []byte {
	w := newWriter()
	w.writeByte(byte(protocol.SecurityLevel))
	w.writeString(protocol.Protocol)
	return w.buf
}

// decodeProtocol deserializes Protocol from bytes matching the TypeScript format
func decodeProtocol(r *readerHoldError) (wallet.Protocol, error) {
	protocol := wallet.Protocol{
		SecurityLevel: wallet.SecurityLevel(r.readByte()),
		Protocol:      r.readString(),
	}
	if r.err != nil {
		return protocol, fmt.Errorf("error decoding protocol: %w", r.err)
	}
	return protocol, nil
}

// encodePrivilegedParams serializes privileged flag and reason matching TypeScript format
func encodePrivilegedParams(privileged *bool, privilegedReason string) []byte {
	w := newWriter()

	// Write privileged flag
	if privileged != nil {
		if *privileged {
			w.writeByte(1)
		} else {
			w.writeByte(0)
		}
	} else {
		// Write 9 bytes of 0xFF (-1) when undefined
		for i := 0; i < 9; i++ {
			w.writeByte(0xFF)
		}
	}

	// Write privileged reason
	if privilegedReason != "" {
		w.writeByte(byte(len(privilegedReason)))
		w.writeString(privilegedReason)
	} else {
		// Write 9 bytes of 0xFF (-1) when undefined
		for i := 0; i < 9; i++ {
			w.writeByte(0xFF)
		}
	}

	return w.buf
}

// decodePrivilegedParams deserializes privileged flag and reason matching TypeScript format
func decodePrivilegedParams(r *readerHoldError) (*bool, string) {
	// Read privileged flag
	var privileged *bool
	flag := r.readByte()
	if flag != 0xFF { // Not -1
		val := flag == 1
		privileged = &val
	}

	// Skip 8 more bytes if flag was 0xFF (TypeScript writes 9 bytes of 0xFF)
	if flag == 0xFF {
		r.readBytes(8)
	}

	// Read privileged reason length
	var privilegedReason string
	reasonLen := r.readByte()
	if reasonLen != 0xFF { // Not -1
		privilegedReason = r.readString()
	} else {
		// Skip 8 more bytes if length was 0xFF (TypeScript writes 9 bytes of 0xFF)
		r.readBytes(8)
	}

	return privileged, privilegedReason
}

// encodeKeyRelatedParams serializes protocol, key and privilege parameters
func encodeKeyRelatedParams(params KeyRelatedParams) ([]byte, error) {
	w := newWriter()

	// Write protocol ID (matches TypeScript format)
	w.writeBytes(encodeProtocol(params.ProtocolID))

	// Write key ID
	w.writeString(params.KeyID)

	// Write counterparty
	if err := encodeCounterparty(w, params.Counterparty); err != nil {
		return nil, err
	}

	// Write privileged params
	w.writeBytes(encodePrivilegedParams(params.Privileged, params.PrivilegedReason))

	return w.buf, nil
}

// decodeKeyRelatedParams deserializes protocol, key and privilege parameters
func decodeKeyRelatedParams(r *readerHoldError) (*KeyRelatedParams, error) {
	params := &KeyRelatedParams{}

	// Read protocol ID (matches TypeScript format)
	protocol, err := decodeProtocol(r)
	if err != nil {
		return nil, fmt.Errorf("error decoding protocol: %w", err)
	}
	params.ProtocolID = protocol

	// Read key ID
	params.KeyID = r.readString()

	// Read counterparty
	params.Counterparty, err = decodeCounterparty(r)
	if err != nil {
		return nil, fmt.Errorf("error decoding counterparty: %w", err)
	}

	// Read privileged params
	params.Privileged, params.PrivilegedReason = decodePrivilegedParams(r)

	if r.err != nil {
		return nil, fmt.Errorf("error decoding key params: %w", r.err)
	}

	return params, nil
}
