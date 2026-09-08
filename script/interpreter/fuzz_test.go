package interpreter

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
)

// FuzzOpcodeParserParse fuzzes the script opcode parser (opcodeparser.go:203),
// the routine that turns untrusted script bytes into opcodes. The invariant is
// that no input panics; where a parse succeeds and unparses, re-parsing the
// unparsed bytes must succeed too.
func FuzzOpcodeParserParse(f *testing.F) {
	seeds := [][]byte{
		{}, // empty script
		// Standard P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
		append(append([]byte{0x76, 0xa9, 0x14}, make([]byte, 20)...), 0x88, 0xac),
		// OP_RETURN with a small data push
		{0x6a, 0x03, 0x01, 0x02, 0x03},
		// Bare pushes of every direct-push length boundary
		{0x01, 0xff},
		{0x4b},                         // OP_DATA_75 with no following data (truncated)
		{0x4c},                         // OP_PUSHDATA1 with no length byte (truncated)
		{0x4c, 0x05, 0x01, 0x02},       // OP_PUSHDATA1 claims 5 bytes, only 2 present
		{0x4d, 0xff, 0xff, 0x00},       // OP_PUSHDATA2 claims 65535 bytes, none present
		{0x4e, 0xff, 0xff, 0xff, 0xff}, // OP_PUSHDATA4 claims 4GiB, none present
		{0x51, 0x52, 0x93},             // OP_1 OP_2 OP_ADD
	}
	for _, s := range seeds {
		f.Add(s)
	}

	parser := &DefaultOpcodeParser{}
	f.Fuzz(func(t *testing.T, data []byte) {
		s := script.NewFromBytes(data)
		parsed, err := parser.Parse(s)
		if err != nil {
			return
		}
		unparsed, err := parser.Unparse(parsed)
		if err != nil {
			return
		}
		if _, err := parser.Parse(unparsed); err != nil {
			t.Fatalf("re-parsing unparsed script failed: %v", err)
		}
	})
}
