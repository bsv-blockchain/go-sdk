package serializer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const outpointSize = 36 // 32 txid + 4 index

// encodeOutpoint converts outpoint string "txid.index" to binary format
func encodeOutpoint(outpoint *wallet.Outpoint) []byte {
	buf := make([]byte, outpointSize)
	if outpoint == nil {
		return buf
	}
	copy(buf[:32], outpoint.Txid[:])
	binary.BigEndian.PutUint32(buf[32:36], outpoint.Index)
	return buf
}

// Outpoint represents a transaction output reference (txid + output index)
type Outpoint string

// encodeOutpoints serializes a slice of outpoints
func encodeOutpoints(outpoints []wallet.Outpoint) ([]byte, error) {
	if outpoints == nil {
		return nil, nil
	}

	w := util.NewWriter()
	w.WriteVarInt(uint64(len(outpoints)))
	for _, outpoint := range outpoints {
		w.WriteBytes(encodeOutpoint(&outpoint))
	}
	return w.Buf, nil
}

// decodeOutpoints deserializes a slice of outpoints
func decodeOutpoints(data []byte) ([]wallet.Outpoint, error) {
	if len(data) == 0 {
		return nil, nil
	}

	r := util.NewReader(data)
	count, err := r.ReadVarInt()
	if err != nil {
		return nil, err
	}
	if util.IsNegativeOne(count) {
		return nil, nil
	}

	outpoints := make([]wallet.Outpoint, 0, count)
	for i := uint64(0); i < count; i++ {
		opBytes, err := r.ReadBytes(outpointSize)
		if err != nil {
			return nil, err
		}
		op, err := decodeOutpointObj(opBytes)
		if err != nil {
			return nil, err
		}
		outpoints = append(outpoints, *op)
	}
	return outpoints, nil
}

// decodeOutpointObj converts binary outpoint data to Outpoint object
func decodeOutpointObj(data []byte) (*wallet.Outpoint, error) {
	if len(data) != outpointSize {
		return nil, errors.New("invalid outpoint data length")
	}
	hash, err := chainhash.NewHash(data[:32])
	if err != nil {
		return nil, fmt.Errorf("error creating chainhash from bytes: %w", err)
	}
	return &wallet.Outpoint{
		Txid:  *hash,
		Index: binary.BigEndian.Uint32(data[32:36]),
	}, nil
}

const (
	counterPartyTypeUninitializedCode uint8 = 0
	counterPartyTypeSelfCode          uint8 = 11
	counterPartyTypeAnyoneCode        uint8 = 12
)

// encodeCounterparty writes counterparty in the same format as TypeScript version
func encodeCounterparty(w *util.Writer, counterparty wallet.Counterparty) error {
	switch counterparty.Type {
	case wallet.CounterpartyUninitialized:
		w.WriteByte(counterPartyTypeUninitializedCode)
	case wallet.CounterpartyTypeSelf:
		w.WriteByte(counterPartyTypeSelfCode)
	case wallet.CounterpartyTypeAnyone:
		w.WriteByte(counterPartyTypeAnyoneCode)
	case wallet.CounterpartyTypeOther:
		if counterparty.Counterparty == nil {
			return errors.New("counterparty is nil for type other")
		}
		w.WriteBytes(counterparty.Counterparty.ToDER())
	default:
		return fmt.Errorf("unknown counterparty type: %v", counterparty.Type)
	}
	return nil
}

// decodeCounterparty reads counterparty in the same format as TypeScript version
func decodeCounterparty(r *util.ReaderHoldError) (wallet.Counterparty, error) {
	counterparty := wallet.Counterparty{}
	counterpartyFlag := r.ReadByte()
	switch counterpartyFlag {
	case counterPartyTypeUninitializedCode:
		counterparty.Type = wallet.CounterpartyUninitialized
	case counterPartyTypeSelfCode:
		counterparty.Type = wallet.CounterpartyTypeSelf
	case counterPartyTypeAnyoneCode:
		counterparty.Type = wallet.CounterpartyTypeAnyone
	default:
		pubKey, err := ec.PublicKeyFromBytes(append([]byte{counterpartyFlag}, r.ReadBytes(32)...))
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
	w := util.NewWriter()
	w.WriteByte(byte(protocol.SecurityLevel))
	w.WriteString(protocol.Protocol)
	return w.Buf
}

// decodeProtocol deserializes Protocol from bytes matching the TypeScript format
func decodeProtocol(r *util.ReaderHoldError) (wallet.Protocol, error) {
	protocol := wallet.Protocol{
		SecurityLevel: wallet.SecurityLevel(r.ReadByte()),
		Protocol:      r.ReadString(),
	}
	if r.Err != nil {
		return protocol, fmt.Errorf("error decoding protocol: %w", r.Err)
	}
	return protocol, nil
}

// encodePrivilegedParams serializes privileged flag and reason matching TypeScript format
func encodePrivilegedParams(privileged *bool, privilegedReason string) []byte {
	w := util.NewWriter()

	// Write privileged flag
	if privileged != nil {
		if *privileged {
			w.WriteByte(1)
		} else {
			w.WriteByte(0)
		}
	} else {
		w.WriteNegativeOne()
	}

	// Write privileged reason
	if privilegedReason != "" {
		w.WriteByte(byte(len(privilegedReason)))
		w.WriteString(privilegedReason)
	} else {
		w.WriteNegativeOne()
	}

	return w.Buf
}

// decodePrivilegedParams deserializes privileged flag and reason matching TypeScript format
func decodePrivilegedParams(r *util.ReaderHoldError) (*bool, string) {
	// Read privileged flag
	var privileged *bool
	flag := r.ReadByte()
	if !util.IsNegativeOneByte(flag) {
		val := flag == 1
		privileged = &val
	} else {
		// Skip 8 more bytes if flag was 0xFF (TypeScript writes 9 bytes of 0xFF)
		r.ReadBytes(8)
	}

	// Read privileged reason length
	var privilegedReason string
	reasonLen := r.ReadByte()
	if !util.IsNegativeOneByte(reasonLen) {
		privilegedReason = r.ReadString()
	} else {
		// Skip 8 more bytes if length was 0xFF (TypeScript writes 9 bytes of 0xFF)
		r.ReadBytes(8)
	}

	return privileged, privilegedReason
}

// encodeKeyRelatedParams serializes protocol, key and privilege parameters
func encodeKeyRelatedParams(params KeyRelatedParams) ([]byte, error) {
	w := util.NewWriter()

	// Write protocol ID (matches TypeScript format)
	w.WriteBytes(encodeProtocol(params.ProtocolID))

	// Write key ID
	w.WriteString(params.KeyID)

	// Write counterparty
	if err := encodeCounterparty(w, params.Counterparty); err != nil {
		return nil, err
	}

	// Write privileged params
	w.WriteBytes(encodePrivilegedParams(params.Privileged, params.PrivilegedReason))

	return w.Buf, nil
}

// decodeKeyRelatedParams deserializes protocol, key and privilege parameters
func decodeKeyRelatedParams(r *util.ReaderHoldError) (*KeyRelatedParams, error) {
	params := &KeyRelatedParams{}

	// Read protocol ID (matches TypeScript format)
	protocol, err := decodeProtocol(r)
	if err != nil {
		return nil, fmt.Errorf("error decoding protocol: %w", err)
	}
	params.ProtocolID = protocol

	// Read key ID
	params.KeyID = r.ReadString()

	// Read counterparty
	params.Counterparty, err = decodeCounterparty(r)
	if err != nil {
		return nil, fmt.Errorf("error decoding counterparty: %w", err)
	}

	// Read privileged params
	params.Privileged, params.PrivilegedReason = decodePrivilegedParams(r)

	if r.Err != nil {
		return nil, fmt.Errorf("error decoding key params: %w", r.Err)
	}

	return params, nil
}
