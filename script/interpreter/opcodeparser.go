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

	// nodeExact selects the parse the script engine uses, which reads a
	// script the way bitcoin-sv does (see parseNodeExact). The zero value
	// keeps the historical behaviour of Parse for other callers.
	nodeExact bool
}

// ParsedOpcode is a parsed opcode.
//
//nolint:recvcheck // mix is intentional: read-only accessors use value receivers since ParsedOpcode is returned by value from State.Opcode() and other non-addressable call sites; mutating helpers use pointer receivers
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
		script.OpCHECKMULTISIG, script.OpCHECKMULTISIGVERIFY:
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

// opcodeMalformed stands in for an instruction that bitcoin-sv's
// CScript::GetOp cannot decode: a push whose length field or data runs past
// the end of the script. GetOp reports such an instruction as
// OP_INVALIDOPCODE (script.h:165-166), which also keeps it clear of every
// helper that matches on opcode values or push data (IsPushOnly and the
// FindAndDelete walk in removeOpcodeByData). Its Data holds the raw script bytes from
// the undecodable instruction to the end of the script, so Unparse is
// lossless. The zero length distinguishes it from a real OP_INVALIDOPCODE.
var opcodeMalformed = opcode{
	val:    script.OpINVALIDOPCODE,
	name:   "OP_MALFORMED_PUSH",
	length: 0,
	exec:   opcodeMalformedPush,
}

// isMalformed reports whether o is the undecodable tail of a script (see
// opcodeMalformed).
func (o *ParsedOpcode) isMalformed() bool {
	return o.op.val == opcodeMalformed.val && o.op.length == opcodeMalformed.length
}

// opcodeMalformedPush fails the script once execution reaches an instruction
// Parse could not decode. Node's EvalScript returns SCRIPT_ERR_BAD_OPCODE as
// soon as GetOp fails, whether or not the current branch is executing
// (interpreter.cpp:441-451).
func opcodeMalformedPush(op *ParsedOpcode, _ *thread) error {
	return errs.NewError(errs.ErrMalformedPush,
		"malformed push: the last %d script bytes do not decode to an instruction", len(op.Data))
}

// decodeInstruction decodes the instruction starting at scr[i] exactly like
// CScript::GetOp2 (script.h:163-198). It returns the offsets of the pushed
// data and the end of the instruction, and ok=false when the push's length
// field or data runs past the end of the script.
func decodeInstruction(scr []byte, i int) (dataStart, end int, ok bool) {
	var size uint64
	switch op := scr[i]; {
	case op < script.OpPUSHDATA1:
		dataStart, size = i+1, uint64(op)
	case op == script.OpPUSHDATA1:
		if len(scr)-(i+1) < 1 {
			return 0, 0, false
		}
		dataStart, size = i+2, uint64(scr[i+1])
	case op == script.OpPUSHDATA2:
		if len(scr)-(i+1) < 2 {
			return 0, 0, false
		}
		dataStart, size = i+3, uint64(binary.LittleEndian.Uint16(scr[i+1:]))
	case op == script.OpPUSHDATA4:
		if len(scr)-(i+1) < 4 {
			return 0, 0, false
		}
		dataStart, size = i+5, uint64(binary.LittleEndian.Uint32(scr[i+1:]))
	default:
		return i + 1, i + 1, true
	}

	if uint64(len(scr)-dataStart) < size { //nolint:gosec // G115 -- dataStart <= len(scr), checked above
		return 0, 0, false
	}

	return dataStart, dataStart + int(size), true //nolint:gosec // G115 -- size <= len(scr)-dataStart, checked above
}

// parseNodeExact decodes every instruction the way bitcoin-sv reads a script,
// including the ones after an OP_RETURN: whether an OP_RETURN ends a script is decided
// when it executes (opcodeReturn), never here. An instruction that cannot be
// decoded does not fail the parse either. It becomes, together with all the
// bytes after it, a final malformed opcode (see opcodeMalformed) that fails
// only when execution reaches it, since node reads instructions lazily and a
// script may legitimately end at a top-level OP_RETURN before its undecodable
// tail (interpreter.cpp:441-451,856-862). The only error it returns is the
// ErrorOnCheckSig one, raised for a checksig opcode anywhere before the first
// OP_RETURN outside every conditional block: that OP_RETURN ends the script
// whenever it is reached, so nothing after it can run.
func (p *DefaultOpcodeParser) parseNodeExact(s *script.Script) (ParsedScript, error) {
	scr := *s

	// First pass: count the instructions so the result is allocated once.
	opcodeCount := 0
	for i := 0; i < len(scr); opcodeCount++ {
		_, end, ok := decodeInstruction(scr, i)
		if !ok {
			opcodeCount++
			break
		}
		i = end
	}

	parsedOps := make(ParsedScript, 0, opcodeCount)
	checkSig := p.ErrorOnCheckSig
	conditionalDepth := 0
	for i := 0; i < len(scr); {
		dataStart, end, ok := decodeInstruction(scr, i)
		if !ok {
			return append(parsedOps, ParsedOpcode{op: opcodeMalformed, Data: scr[i:]}), nil
		}

		parsedOp := ParsedOpcode{op: opcodeArray[scr[i]]}
		if checkSig {
			if parsedOp.RequiresTx() {
				return nil, errs.NewError(errs.ErrInvalidParams, "tx and previous output must be supplied for checksig")
			}
			// Counting OP_VERIF/OP_VERNOTIF as conditionals only ever
			// over-estimates the depth at run time, where they may be NOPs.
			switch parsedOp.op.val {
			case script.OpIF, script.OpNOTIF, script.OpVERIF, script.OpVERNOTIF:
				conditionalDepth++
			case script.OpENDIF:
				conditionalDepth = max(conditionalDepth-1, 0)
			case script.OpRETURN:
				checkSig = conditionalDepth > 0
			}
		}
		if parsedOp.op.val != script.Op0 && parsedOp.op.val <= script.OpPUSHDATA4 {
			parsedOp.Data = scr[dataStart:end]
		}

		parsedOps = append(parsedOps, parsedOp)
		i = end
	}

	return parsedOps, nil
}

// Parse takes a *script.Script and returns a []interpreter.ParsedOp.
//
// A zero-value DefaultOpcodeParser keeps everything after an OP_RETURN that is
// outside every conditional block as that OP_RETURN's Data and returns an
// error for an undecodable push. The script engine instead parses scripts the
// way bitcoin-sv reads them (see parseNodeExact).
func (p *DefaultOpcodeParser) Parse(s *script.Script) (ParsedScript, error) {
	if p.nodeExact {
		return p.parseNodeExact(s)
	}
	return p.parseLegacy(s)
}

// parseLegacy is the parse Parse has always performed for callers outside the
// script engine: everything after an OP_RETURN outside every conditional block
// is kept as that OP_RETURN's Data, and an undecodable push is an error.
func (p *DefaultOpcodeParser) parseLegacy(s *script.Script) (ParsedScript, error) {
	scr := *s

	// First pass: count opcodes
	opcodeCount := 0
	i := 0
	conditionalDepth := 0

	for i < len(scr) {
		instruction := scr[i]
		op := opcodeArray[instruction]

		// Track conditionals and check for OP_RETURN
		if isOpReturnOutsideConditional := updateConditionalDepth(op.val, &conditionalDepth); isOpReturnOutsideConditional {
			opcodeCount++
			// OP_RETURN outside conditionals consumes rest of script
			break
		}

		// Special handling for OP_RETURN inside conditionals
		if op.val == script.OpRETURN {
			// Inside conditional, just skip the single byte
			i++
			opcodeCount++
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

		// Track conditionals and check for OP_RETURN
		if isOpReturnOutsideConditional := updateConditionalDepth(parsedOp.op.val, &conditionalBlock); isOpReturnOutsideConditional {
			// OP_RETURN outside conditionals - extract remaining data and return
			if i+1 < len(scr) {
				parsedOp.Data = scr[i+1:]
				parsedOp.op.length = 1 + len(parsedOp.Data)
			}
			parsedOps = append(parsedOps, parsedOp)
			return parsedOps, nil
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

// updateConditionalDepth updates the conditional depth based on the opcode
// Returns true if this is an OP_RETURN outside of conditionals
func updateConditionalDepth(op byte, depth *int) bool {
	switch op {
	case script.OpIF, script.OpNOTIF, script.OpVERIF, script.OpVERNOTIF:
		*depth++
	case script.OpENDIF:
		if *depth > 0 {
			*depth--
		}
	case script.OpRETURN:
		return *depth == 0
	}
	return false
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

// IsPushOnly returns true if the ParsedScript only contains push commands.
// Like node's CScript::IsPushOnly, a script with an undecodable instruction
// is not push only.
func (p ParsedScript) IsPushOnly() bool {
	for _, op := range p {
		if op.op.val > script.Op16 {
			return false
		}
	}

	return true
}

// isP2SH reports whether p is the pay-to-script-hash pattern (OP_HASH160
// <20 bytes> OP_EQUAL), the parsed-opcode equivalent of *script.Script's
// IsP2SH: node's own IsP2SH checks the same three bytes on the raw script
// (script.cpp:164-168), which is what an exact push-20 opcode and an exact
// 3-opcode script reduce to once parsed. Used to re-derive t.bip16 in
// thread.checkParsedScriptFlags, which apply() and SetState both call --
// SetState never has the original *script.Script to call *script.Script's
// own IsP2SH on, only the parsed form State.Scripts carries.
func (p ParsedScript) isP2SH() bool {
	return len(p) == 3 &&
		p[0].op.val == script.OpHASH160 &&
		p[1].op.val == script.OpDATA20 && len(p[1].Data) == 20 &&
		p[2].op.val == script.OpEQUAL
}

// removeOpcodeByData returns scriptCode with every instruction whose raw
// bytes equal canonicalPush(data) removed, mirroring node's
// scriptCode.FindAndDelete(CScript(data)) (script.h:200-222) byte for byte:
//
//   - only whole instructions are compared, at the instruction boundaries
//     GetOp walks, so a push of different (e.g. longer) data that merely
//     contains the target is kept, and so is a non-canonical encoding of the
//     same data (PUSHDATA1 for a short push, a PUSHDATA-encoded empty push);
//   - an empty data is encoded as the single OP_0 byte, so it removes OP_0
//     instructions and nothing else;
//   - the walk does not stop at OP_RETURN (the bytes after a top-level
//     OP_RETURN are instructions to GetOp too), and at the first malformed
//     instruction it stops and keeps the rest of the script verbatim.
//
// It works on the serialised scriptCode rather than a ParsedScript because
// a ParsedScript keeps a malformed tail as one opcode, and a post-Chronicle
// unlocking-script scriptCode continues into the appended locking script
// without an instruction boundary in between.
func removeOpcodeByData(scriptCode, data []byte) []byte {
	pattern := canonicalPush(data)
	result := make([]byte, 0, len(scriptCode))
	pc, pc2 := 0, 0
	for {
		result = append(result, scriptCode[pc2:pc]...)
		for len(scriptCode)-pc >= len(pattern) && bytes.Equal(scriptCode[pc:pc+len(pattern)], pattern) {
			pc += len(pattern)
		}
		pc2 = pc

		// GetOp (script.cpp GetScriptOp): step over one instruction, or stop
		// at the end or at a malformed one.
		if pc >= len(scriptCode) {
			break
		}
		opcode := scriptCode[pc]
		pc++
		if opcode > script.OpPUSHDATA4 {
			continue
		}
		size, sizeLen := uint64(opcode), 0
		switch opcode {
		case script.OpPUSHDATA1:
			sizeLen = 1
		case script.OpPUSHDATA2:
			sizeLen = 2
		case script.OpPUSHDATA4:
			sizeLen = 4
		}
		if len(scriptCode)-pc < sizeLen {
			break
		}
		if sizeLen > 0 {
			var buf [8]byte
			copy(buf[:], scriptCode[pc:pc+sizeLen])
			size = binary.LittleEndian.Uint64(buf[:])
			pc += sizeLen
		}
		if uint64(len(scriptCode)-pc) < size { //nolint:gosec // G115 -- pc <= len(scriptCode)
			break
		}
		pc += int(size)
	}
	return append(result, scriptCode[pc2:]...)
}

// canonicalPush returns data encoded as a single push instruction exactly as
// node's CScript(const std::vector<uint8_t>&) builds it (script.h:71,
// 102-131): the shortest length prefix for its size and never an
// OP_1..OP_16/OP_1NEGATE shortcut, so a one-byte 0x05 is 01 05 and an empty
// data is the single byte 00 (OP_0).
func canonicalPush(data []byte) []byte {
	push := make([]byte, 0, 5+len(data))
	switch l := len(data); {
	case l < int(script.OpPUSHDATA1):
		push = append(push, byte(l))
	case l <= 0xff:
		push = append(push, script.OpPUSHDATA1, byte(l))
	case l <= 0xffff:
		push = binary.LittleEndian.AppendUint16(append(push, script.OpPUSHDATA2), uint16(l))
	default:
		push = binary.LittleEndian.AppendUint32(append(push, script.OpPUSHDATA4), uint32(l)) //nolint:gosec // G115 -- a stack element is far below 4 GiB
	}
	return append(push, data...)
}

// bytes returns any data associated with the opcode encoded as it would be in
// a script.  This is used for unparsing scripts from parsed opcodes.
func (o *ParsedOpcode) bytes() ([]byte, error) {
	if o.isMalformed() {
		return o.Data, nil
	}

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
			retbytes = append(retbytes, byte(l)) //nolint:gosec // G115 -- OP_PUSHDATA1 data length is bounded to a single byte (0-255) by opcode encoding
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
		return nil, errs.NewError(
			errs.ErrInternal,
			"internal consistency error - parsed opcode %s has data length %d when %d was expected",
			o.Name(), len(retbytes), nbytes,
		)
	}

	return retbytes, nil
}
