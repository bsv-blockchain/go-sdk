package interpreter

import (
	"bytes"
	"encoding/binary"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/errs"
)

// OpcodeParser parses *script.Script into a ParsedScript, and unparsing back
type OpcodeParser interface {
	Parse(*script.Script) (ParsedScript, error)
	Unparse(ParsedScript) (*script.Script, error)
}

// ParsedScript is a slice of ParsedOp
type ParsedScript []ParsedOpcode

// DefaultOpcodeParser is a standard parser which can be used from zero value.
type DefaultOpcodeParser struct {
	ErrorOnCheckSig bool
}

// ParsedOpcode is a parsed opcode.
type ParsedOpcode struct {
	op   opcode
	Data []byte
}

// Name returns the human readable name for the current opcode.
func (o ParsedOpcode) Name() string {
	return o.op.name
}

// Value returns the byte value of the opcode.
func (o ParsedOpcode) Value() byte {
	return o.op.val
}

// Length returns the data length of the opcode.
func (o ParsedOpcode) Length() int {
	return o.op.length
}

// IsDisabled returns true if the op is disabled.
func (o *ParsedOpcode) IsDisabled() bool {
	switch o.op.val {
	case script.Op2MUL, script.Op2DIV:
		return true
	default:
		return false
	}
}

// RequiresTx returns true if the op is checksig.
func (o *ParsedOpcode) RequiresTx() bool {
	switch o.op.val {
	case script.OpCHECKSIG, script.OpCHECKSIGVERIFY,
		script.OpCHECKMULTISIG, script.OpCHECKMULTISIGVERIFY, script.OpCHECKSEQUENCEVERIFY:
		return true
	default:
		return false
	}
}

// AlwaysIllegal returns true if the op is always illegal.
func (o *ParsedOpcode) AlwaysIllegal() bool {
	switch o.op.val {
	case script.OpVERIF, script.OpVERNOTIF:
		return true
	default:
		return false
	}
}

// IsConditional returns true if the op is a conditional.
func (o *ParsedOpcode) IsConditional() bool {
	switch o.op.val {
	case script.OpIF, script.OpNOTIF, script.OpELSE, script.OpENDIF, script.OpVERIF, script.OpVERNOTIF:
		return true
	default:
		return false
	}
}

// enforceMinimumDataPush checks that the op is pushing only the needed amount of data.
// Errs if not the case.
func (o *ParsedOpcode) enforceMinimumDataPush() error {
	dataLen := len(o.Data)
	if dataLen == 0 && o.op.val != script.Op0 {
		return errs.NewError(
			errs.ErrMinimalData,
			"zero length data push is encoded with opcode %s instead of OP_0",
			o.op.name,
		)
	}
	if dataLen == 1 && (1 <= o.Data[0] && o.Data[0] <= 16) && o.op.val != script.Op1+o.Data[0]-1 {
		return errs.NewError(
			errs.ErrMinimalData,
			"data push of the value %d encoded with opcode %s instead of OP_%d", o.Data[0], o.op.name, o.Data[0],
		)
	}
	if dataLen == 1 && o.Data[0] == 0x81 && o.op.val != script.Op1NEGATE {
		return errs.NewError(
			errs.ErrMinimalData,
			"data push of the value -1 encoded with opcode %s instead of OP_1NEGATE", o.op.name,
		)
	}
	if dataLen <= 75 {
		if int(o.op.val) != dataLen {
			return errs.NewError(
				errs.ErrMinimalData,
				"data push of %d bytes encoded with opcode %s instead of OP_DATA_%d", dataLen, o.op.name, dataLen,
			)
		}
	} else if dataLen <= 255 {
		if o.op.val != script.OpPUSHDATA1 {
			return errs.NewError(
				errs.ErrMinimalData,
				"data push of %d bytes encoded with opcode %s instead of OP_PUSHDATA1", dataLen, o.op.name,
			)
		}
	} else if dataLen <= 65535 {
		if o.op.val != script.OpPUSHDATA2 {
			return errs.NewError(
				errs.ErrMinimalData,
				"data push of %d bytes encoded with opcode %s instead of OP_PUSHDATA2", dataLen, o.op.name,
			)
		}
	}
	return nil
}

// advancePosition calculates the next position after parsing an opcode
func advancePosition(scr []byte, i int, op byte) (int, error) {
	switch op {
	case script.OpPUSHDATA1:
		if len(scr) < i+2 {
			return 0, errs.NewError(errs.ErrMalformedPush, "script truncated")
		}
		dataLen := int(scr[i+1])
		newPos := i + 2 + dataLen
		if newPos > len(scr) {
			return 0, errs.NewError(errs.ErrMalformedPush, "push data exceeds script length")
		}
		return newPos, nil
		
	case script.OpPUSHDATA2:
		if len(scr) < i+3 {
			return 0, errs.NewError(errs.ErrMalformedPush, "script truncated")
		}
		dataLen := int(binary.LittleEndian.Uint16(scr[i+1:]))
		newPos := i + 3 + dataLen
		if newPos > len(scr) {
			return 0, errs.NewError(errs.ErrMalformedPush, "push data exceeds script length")
		}
		return newPos, nil
		
	case script.OpPUSHDATA4:
		if len(scr) < i+5 {
			return 0, errs.NewError(errs.ErrMalformedPush, "script truncated")
		}
		dataLen := int(binary.LittleEndian.Uint32(scr[i+1:]))
		newPos := i + 5 + dataLen
		if newPos > len(scr) {
			return 0, errs.NewError(errs.ErrMalformedPush, "push data exceeds script length")
		}
		return newPos, nil
		
	default:
		// For other opcodes, we need to check opcodeArray
		opInfo := opcodeArray[op]
		if opInfo.length > 1 {
			if i+opInfo.length > len(scr) {
				return 0, errs.NewError(errs.ErrMalformedPush, "script truncated")
			}
			return i + opInfo.length, nil
		}
		return i + 1, nil
	}
}

// Parse takes a *script.Script and returns a []interpreter.ParsedOp
func (p *DefaultOpcodeParser) Parse(s *script.Script) (ParsedScript, error) {
	scr := *s
	
	// First pass: count opcodes
	opcodeCount := 0
	i := 0
	conditionalDepth := 0
	
	for i < len(scr) {
		instruction := scr[i]
		op := opcodeArray[instruction]
		
		// Track conditionals to know if OP_RETURN will consume the script
		switch op.val {
		case script.OpIF, script.OpNOTIF, script.OpVERIF, script.OpVERNOTIF:
			conditionalDepth++
		case script.OpENDIF:
			if conditionalDepth > 0 {
				conditionalDepth--
			}
		case script.OpRETURN:
			opcodeCount++
			// OP_RETURN outside conditionals consumes rest of script
			if conditionalDepth == 0 {
				// Rest of script becomes data for OP_RETURN
				i = len(scr)
				break
			}
			// Inside conditional, just skip the single byte
			i++
			continue
		}
		
		// Skip to next opcode
		newPos, err := advancePosition(scr, i, instruction)
		if err != nil {
			return nil, err
		}
		i = newPos
		
		opcodeCount++
	}
	
	// Second pass: allocate exactly what we need and parse
	parsedOps := make([]ParsedOpcode, 0, opcodeCount)
	conditionalBlock := 0

	for i := 0; i < len(scr); {
		instruction := scr[i]

		parsedOp := ParsedOpcode{op: opcodeArray[instruction]}
		if p.ErrorOnCheckSig && parsedOp.RequiresTx() {
			return nil, errs.NewError(errs.ErrInvalidParams, "tx and previous output must be supplied for checksig")
		}

		switch parsedOp.op.val {
		case script.OpIF, script.OpNOTIF, script.OpVERIF, script.OpVERNOTIF:
			conditionalBlock++
		case script.OpENDIF:
			conditionalBlock--
		case script.OpRETURN:
			// If we are not in a conditional block, we end script evaluation.
			// This must be the final evaluated opcode, everything after is ignored.
			if conditionalBlock == 0 {
				if i+1 < len(scr) {
					parsedOp.Data = scr[i+1:]
					parsedOp.op.length = 1 + len(parsedOp.Data)
				}
				parsedOps = append(parsedOps, parsedOp)
				return parsedOps, nil
			}
			// If we are in an conditional block, we continue parsing the other branches,
			// therefore all data must adhere to push data rules.
		}

		// Extract data for this opcode
		switch parsedOp.op.val {
		case script.OpPUSHDATA1:
			if len(scr) >= i+2 {
				dataLen := int(scr[i+1])
				if len(scr) >= i+2+dataLen {
					parsedOp.Data = scr[i+2 : i+2+dataLen]
				}
			}
		case script.OpPUSHDATA2:
			if len(scr) >= i+3 {
				dataLen := int(binary.LittleEndian.Uint16(scr[i+1:]))
				if len(scr) >= i+3+dataLen {
					parsedOp.Data = scr[i+3 : i+3+dataLen]
				}
			}
		case script.OpPUSHDATA4:
			if len(scr) >= i+5 {
				dataLen := int(binary.LittleEndian.Uint32(scr[i+1:]))
				if len(scr) >= i+5+dataLen {
					parsedOp.Data = scr[i+5 : i+5+dataLen]
				}
			}
		default:
			// Fixed length opcodes
			if parsedOp.op.length > 1 && len(scr[i:]) >= parsedOp.op.length {
				parsedOp.Data = scr[i+1 : i+parsedOp.op.length]
			}
		}
		
		// Advance position using the same logic as first pass
		newPos, err := advancePosition(scr, i, instruction)
		if err != nil {
			// This shouldn't happen since first pass validated
			return nil, err
		}
		i = newPos

		parsedOps = append(parsedOps, parsedOp)
	}
	return parsedOps, nil
}

// Unparse reverses the action of Parse and returns the
// ParsedScript as a *script.Script
func (p *DefaultOpcodeParser) Unparse(pscr ParsedScript) (*script.Script, error) {
	script := make(script.Script, 0, len(pscr))
	for _, pop := range pscr {
		b, err := pop.bytes()
		if err != nil {
			return nil, err
		}
		script = append(script, b...)
	}
	return &script, nil
}

// IsPushOnly returns true if the ParsedScript only contains push commands
func (p ParsedScript) IsPushOnly() bool {
	for _, op := range p {
		if op.op.val > script.Op16 {
			return false
		}
	}

	return true
}

// removeOpcodeByData will return the script minus any opcodes that would push
// the passed data to the stack.
func (p ParsedScript) removeOpcodeByData(data []byte) ParsedScript {
	retScript := make(ParsedScript, 0, len(p))
	for _, pop := range p {
		if !pop.canonicalPush() || !bytes.Contains(pop.Data, data) {
			retScript = append(retScript, pop)
		}
	}

	return retScript
}

func (p ParsedScript) removeOpcode(opcode byte) ParsedScript {
	retScript := make(ParsedScript, 0, len(p))
	for _, pop := range p {
		if pop.op.val != opcode {
			retScript = append(retScript, pop)
		}
	}

	return retScript
}

// canonicalPush returns true if the object is either not a push instruction
// or the push instruction contained wherein is matches the canonical form
// or using the smallest instruction to do the job. False otherwise.
func (o ParsedOpcode) canonicalPush() bool {
	opcode := o.op.val
	data := o.Data
	dataLen := len(o.Data)
	if opcode > script.Op16 {
		return true
	}

	if opcode < script.OpPUSHDATA1 && opcode > script.Op0 && (dataLen == 1 && data[0] <= 16) {
		return false
	}
	if opcode == script.OpPUSHDATA1 && dataLen < int(script.OpPUSHDATA1) {
		return false
	}
	if opcode == script.OpPUSHDATA2 && dataLen <= 0xff {
		return false
	}
	if opcode == script.OpPUSHDATA4 && dataLen <= 0xffff {
		return false
	}
	return true
}

// bytes returns any data associated with the opcode encoded as it would be in
// a script.  This is used for unparsing scripts from parsed opcodes.
func (o *ParsedOpcode) bytes() ([]byte, error) {
	var retbytes []byte
	if o.op.length > 0 {
		retbytes = make([]byte, 1, o.op.length)
	} else {
		retbytes = make([]byte, 1, 1+len(o.Data)-
			o.op.length)
	}

	retbytes[0] = o.op.val
	if o.op.length == 1 {
		if len(o.Data) != 0 {
			return nil, errs.NewError(
				errs.ErrInternal,
				"internal consistency error - parsed opcode %s has data length %d when %d was expected",
				o.Name(), len(o.Data), 0,
			)
		}
		return retbytes, nil
	}
	nbytes := o.op.length
	if o.op.length < 0 {
		l := len(o.Data)
		// tempting just to hardcode to avoid the complexity here.
		switch o.op.length {
		case -1:
			retbytes = append(retbytes, byte(l))
			nbytes = int(retbytes[1]) + len(retbytes)
		case -2:
			retbytes = append(retbytes, byte(l&0xff),
				byte(l>>8&0xff))
			nbytes = int(binary.LittleEndian.Uint16(retbytes[1:])) +
				len(retbytes)
		case -4:
			retbytes = append(retbytes, byte(l&0xff),
				byte((l>>8)&0xff), byte((l>>16)&0xff),
				byte((l>>24)&0xff))
			nbytes = int(binary.LittleEndian.Uint32(retbytes[1:])) +
				len(retbytes)
		}
	}

	retbytes = append(retbytes, o.Data...)

	if len(retbytes) != nbytes {
		return nil, errs.NewError(errs.ErrInternal,
			"internal consistency error - parsed opcode %s has data length %d when %d was expected",
			o.Name(), len(retbytes), nbytes,
		)
	}

	return retbytes, nil
}
