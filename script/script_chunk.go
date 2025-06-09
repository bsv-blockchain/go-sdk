package script

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
)

type ScriptChunk struct {
	Op   byte
	Data []byte
}

func (op *ScriptChunk) String() string {
	if op.Op > Op0 && op.Op <= OpPUSHDATA4 {
		return hex.EncodeToString(op.Data)
	}
	return OpCodeValues[op.Op]
}

// ReadOp reads the next script operation from the Script starting at the given position.
// It returns the parsed ScriptOp and any error encountered during parsing.
// The position is updated to point to the next operation in the Script.
func (s *Script) ReadOp(pos *int) (op *ScriptChunk, err error) {
	b := *s
	if len(b) <= *pos {
		err = ErrScriptIndexOutOfRange
		return
	}
	switch b[*pos] {
	case OpPUSHDATA1:
		if len(b) < *pos+2 {
			err = ErrDataTooSmall
			return
		}

		l := int(b[*pos+1])
		*pos += 2

		if len(b) < *pos+l {
			err = ErrDataTooSmall
			return
		}

		op = &ScriptChunk{Op: OpPUSHDATA1, Data: b[*pos : *pos+l]}
		*pos += l

	case OpPUSHDATA2:
		if len(b) < *pos+3 {
			err = ErrDataTooSmall
			return
		}

		l := int(binary.LittleEndian.Uint16(b[*pos+1:]))
		*pos += 3

		if len(b) < *pos+l {
			err = ErrDataTooSmall
			return
		}

		op = &ScriptChunk{Op: OpPUSHDATA2, Data: b[*pos : *pos+l]}
		*pos += l

	case OpPUSHDATA4:
		if len(b) < *pos+5 {
			err = ErrDataTooSmall
			return
		}

		l := int(binary.LittleEndian.Uint32(b[*pos+1:]))
		*pos += 5

		if len(b) < *pos+l {
			err = ErrDataTooSmall
			return
		}

		op = &ScriptChunk{Op: OpPUSHDATA4, Data: b[*pos : *pos+l]}
		*pos += l

	default:
		if b[*pos] >= OpDATA1 && b[*pos] < OpPUSHDATA1 {
			l := b[*pos]
			if len(b) < *pos+int(1+l) {
				err = ErrDataTooSmall
				return
			}
			op = &ScriptChunk{Op: b[*pos], Data: b[*pos+1 : *pos+int(l+1)]}
			*pos += int(1 + l)
		} else {
			op = &ScriptChunk{Op: b[*pos]}
			*pos++
		}
	}

	return
}

// ParseOps parses the script and returns a slice of ScriptOp objects.
// It returns the parsed ScriptOps and any error encountered during parsing.
func (s *Script) ParseOps() (ops []*ScriptChunk, err error) {
	pos := 0
	for pos < len(*s) {
		op, err := s.ReadOp(&pos)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}

	return
}

// NewScriptFromScriptOps creates a new Script from a slice of ScriptOps.
// It returns the new Script and any error encountered during parsing.
func NewScriptFromScriptOps(parts []*ScriptChunk) (*Script, error) {
	length := 0
	for _, p := range parts {
		// op code
		length++

		switch p.Op {
		case OpPUSHDATA1:
			// length of data + 1 byte for length
			length += 1 + len(p.Data)
		case OpPUSHDATA2:
			// length of data + 2 bytes for length
			length += 2 + len(p.Data)
		case OpPUSHDATA4:
			// length of data + 4 bytes for length
			length += 4 + len(p.Data)
		case OpRETURN:
			length += len(p.Data)
		default:
			if p.Op >= OpDATA1 && p.Op < OpPUSHDATA1 {
				// length of data
				length += len(p.Data)
			}
		}
	}

	s := make(Script, 0, length)
	for _, p := range parts {
		if p.Op >= OpDATA1 && p.Op <= OpPUSHDATA4 {
			err := s.AppendPushData(p.Data)
			if err != nil {
				return nil, err
			}
		} else {
			err := s.AppendOpcodes(p.Op)
			if err != nil {
				return nil, err
			}
		}
		if p.Op == OpRETURN && len(p.Data) > 0 {
			s = append(s, p.Data...)
			break
		}
	}
	return &s, nil
}

// EncodePushDatas takes an array of byte slices and returns a single byte
// slice with the appropriate OP_PUSH commands embedded. The output
// can be encoded to a hex string and viewed as a BitCoin script hex
// string.
//
// For example '76a9140d6cf2ef7bc915d109f77357a71b64fc25e2e11488ac' is
// the hex string of a P2PKH output script.
func EncodePushDatas(parts [][]byte) ([]byte, error) {
	b := make([]byte, 0)

	for i, part := range parts {
		pd, err := PushDataPrefix(part)
		if err != nil {
			return nil, fmt.Errorf("%w '%d'", ErrPartTooBig, i)
		}

		b = append(b, pd...)
		b = append(b, part...)
	}

	return b, nil
}

// PushDataPrefix takes a single byte slice of data and returns its
// OP_PUSHDATA BitCoin encoding prefix based on its length.
//
// For example, the data byte slice '022a8c1a18378885db9054676f17a27f4219045e'
// would be encoded as '14022a8c1a18378885db9054676f17a27f4219045e' in BitCoin.
// The OP_PUSHDATA prefix is '14' since the length of the data is
// 20 bytes (0x14 in decimal is 20).
func PushDataPrefix(data []byte) ([]byte, error) {
	b := make([]byte, 0)
	l := int64(len(data))

	if l <= 75 {
		b = append(b, byte(l))

	} else if l <= 0xFF {
		b = append(b, OpPUSHDATA1)
		b = append(b, byte(len(data)))

	} else if l <= 0xFFFF {
		b = append(b, OpPUSHDATA2)
		lenBuf := make([]byte, 2)
		binary.LittleEndian.PutUint16(lenBuf, uint16(len(data)))
		b = append(b, lenBuf...)

	} else if l <= 0xFFFFFFFF { // transaction.DefaultSequenceNumber
		b = append(b, OpPUSHDATA4)
		lenBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBuf, uint32(len(data)))
		b = append(b, lenBuf...)

	} else {
		return nil, ErrDataTooBig
	}

	return b, nil
}

// DecodeScriptHex takes a hex string and decodes the opcodes in it
// returning an array of opcode parts (which could be opcodes or data
// pushed to the stack).
func DecodeScriptHex(s string) ([]*ScriptChunk, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return DecodeScript(b)
}

type DecodeOptions int

const (
	DecodeOptionsParseOpReturn DecodeOptions = 0
)

// DecodeScript takes bytes and decodes the opcodes in it
// returning an array of opcode parts (which could be opcodes or data
// pushed to the stack).
func DecodeScript(b []byte, options ...DecodeOptions) ([]*ScriptChunk, error) {
	var ops []*ScriptChunk
	conditionalBlock := 0
	for len(b) > 0 {
		// Handle OP codes
		op := &ScriptChunk{Op: b[0]}
		switch op.Op {
		case OpIF, OpNOTIF, OpVERIF, OpVERNOTIF:
			conditionalBlock++
			b = b[1:]
		case OpENDIF:
			conditionalBlock--
			b = b[1:]
		case OpRETURN:
			if (slices.Contains(options, DecodeOptionsParseOpReturn)) || conditionalBlock > 0 {
				b = b[1:]
			} else {
				op.Data = b
				b = nil
			}
		case OpPUSHDATA1:
			if len(b) < 2 {
				return ops, ErrDataTooSmall
			}

			l := int(b[1])
			b = b[2:]

			if len(b) < l {
				return ops, ErrDataTooSmall
			}
			op.Data = b[:l]
			b = b[l:]

		case OpPUSHDATA2:
			if len(b) < 3 {
				return ops, ErrDataTooSmall
			}

			l := int(binary.LittleEndian.Uint16(b[1:]))

			b = b[3:]

			if len(b) < l {
				return ops, ErrDataTooSmall
			}
			op.Data = b[:l]
			b = b[l:]

		case OpPUSHDATA4:
			if len(b) < 5 {
				return ops, ErrDataTooSmall
			}

			l := int(binary.LittleEndian.Uint32(b[1:]))

			b = b[5:]

			if len(b) < l {
				return ops, ErrDataTooSmall
			}

			op.Data = b[:l]
			b = b[l:]

		default:
			if op.Op >= 0x01 && op.Op <= OpPUSHDATA4 {
				l := op.Op
				if len(b) < int(1+l) {
					return ops, ErrDataTooSmall
				}
				op.Data = b[1 : 1+l]
				b = b[1+l:]
			} else {
				b = b[1:]
			}
		}
		ops = append(ops, op)
	}

	return ops, nil
}
