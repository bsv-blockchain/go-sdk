// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package interpreter

import (
	"math/big"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/errs"
	"github.com/stretchr/testify/require"
)

// TestOpcodeDisabled tests the opcodeDisabled function manually because all
// disabled opcodes result in a script execution failure when executed normally,
// so the function is not called under normal circumstances.
func TestOpcodeDisabled(t *testing.T) {
	t.Parallel()

	tests := []byte{script.Op2MUL, script.Op2DIV}
	for _, opcodeVal := range tests {
		pop := ParsedOpcode{op: opcodeArray[opcodeVal], Data: nil}
		err := opcodeDisabled(&pop, nil)
		if !errs.IsErrorCode(err, errs.ErrDisabledOpcode) {
			t.Errorf("opcodeDisabled: unexpected error - got %v, "+
				"want %v", err, errs.ErrDisabledOpcode)
			continue
		}
	}
}

func TestParse(t *testing.T) {
	tt := []struct {
		name            string
		scriptHexString string

		expectedParsedScript ParsedScript
	}{
		{
			name:            "1 op return",
			scriptHexString: "0168776a0024dc",

			expectedParsedScript: ParsedScript{
				ParsedOpcode{
					op: opcode{
						val:    script.OpDATA1,
						name:   "OP_DATA_1",
						length: 2,
						exec:   opcodePushData,
					},
					Data: []byte{script.OpENDIF},
				},
				ParsedOpcode{
					op: opcode{
						val:    script.OpNIP,
						name:   "OP_NIP",
						length: 1,
						exec:   opcodeNip,
					},
					Data: nil,
				},
				ParsedOpcode{
					op: opcode{
						val:    script.OpRETURN,
						name:   "OP_RETURN",
						length: 4,
						exec:   opcodeReturn,
					},
					Data: []byte{0x00, 0x24, 0xDC},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			s, err := script.NewFromHex(tc.scriptHexString)
			require.NoError(t, err)

			codeParser := DefaultOpcodeParser{}
			p, err := codeParser.Parse(s)
			require.NoError(t, err)

			for i := range p {
				require.Equal(t, tc.expectedParsedScript[i].Data, p[i].Data)
				require.Equal(t, tc.expectedParsedScript[i].op.length, p[i].op.length)
				require.Equal(t, tc.expectedParsedScript[i].op.name, p[i].op.name)
				require.Equal(t, tc.expectedParsedScript[i].op.val, p[i].op.val)
			}
		})
	}
}

func TestOpShift(t *testing.T) {
	t.Parallel()

	// Tests can be found https://github.com/bitcoin-sv/bitcoin-sv/blob/86eb5e8bdf5573c3cd844a1d81bd4fb151b909e0/src/test/opcode_tests.cpp#L640

	tests := []struct {
		name     string
		initial  []byte
		shift    int64
		op       byte
		expected []byte
	}{
		{"", []byte{}, 0, script.OpRSHIFT, []byte{}},
		{"", []byte{}, 0x01, script.OpRSHIFT, []byte{}},
		{"", []byte{}, 0x02, script.OpRSHIFT, []byte{}},
		{"", []byte{}, 0x07, script.OpRSHIFT, []byte{}},
		{"", []byte{}, 0x08, script.OpRSHIFT, []byte{}},
		{"", []byte{}, 0x09, script.OpRSHIFT, []byte{}},
		{"", []byte{}, 0x0F, script.OpRSHIFT, []byte{}},
		{"", []byte{}, 0x10, script.OpRSHIFT, []byte{}},
		{"", []byte{}, 0x11, script.OpRSHIFT, []byte{}},

		{"", []byte{0xFF}, 0, script.OpRSHIFT, []byte{0b11111111}},
		{"", []byte{0xFF}, 0x01, script.OpRSHIFT, []byte{0b01111111}},
		{"", []byte{0xFF}, 0x02, script.OpRSHIFT, []byte{0b00111111}},
		{"", []byte{0xFF}, 0x03, script.OpRSHIFT, []byte{0b00011111}},
		{"", []byte{0xFF}, 0x04, script.OpRSHIFT, []byte{0b00001111}},
		{"", []byte{0xFF}, 0x05, script.OpRSHIFT, []byte{0b00000111}},
		{"", []byte{0xFF}, 0x06, script.OpRSHIFT, []byte{0b00000011}},
		{"", []byte{0xFF}, 0x07, script.OpRSHIFT, []byte{0b00000001}},
		{"", []byte{0xFF}, 0x08, script.OpRSHIFT, []byte{0b00000000}},

		{"", []byte{0xFF}, 0x01, script.OpRSHIFT, []byte{0x7F}},
		{"", []byte{0xFF}, 0x02, script.OpRSHIFT, []byte{0x3F}},
		{"", []byte{0xFF}, 0x03, script.OpRSHIFT, []byte{0x1F}},
		{"", []byte{0xFF}, 0x04, script.OpRSHIFT, []byte{0x0F}},
		{"", []byte{0xFF}, 0x05, script.OpRSHIFT, []byte{0x07}},
		{"", []byte{0xFF}, 0x06, script.OpRSHIFT, []byte{0x03}},
		{"", []byte{0xFF}, 0x07, script.OpRSHIFT, []byte{0x01}},

		// bitpattern, not a number so not reduced to zero bytes
		{"", []byte{0xFF}, 0x08, script.OpRSHIFT, []byte{0x00}},

		// shift single bit over byte boundary
		{"", []byte{0x01, 0x00}, 0x01, script.OpRSHIFT, []byte{0x00, 0x80}},
		{"", []byte{0x01, 0x00, 0x00}, 0x01, script.OpRSHIFT, []byte{0x00, 0x80, 0x00}},
		{"", []byte{0x00, 0x01, 0x00}, 0x01, script.OpRSHIFT, []byte{0x00, 0x00, 0x80}},
		{"", []byte{0x00, 0x00, 0x01}, 0x01, script.OpRSHIFT, []byte{0x00, 0x00, 0x00}},

		// []byte{0x9F, 0x11, 0xF5, 0x55} is a sequence of bytes that is equal to the bit pattern
		// "1001 1111 0001 0001 1111 0101 0101 0101"
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0, script.OpRSHIFT, []byte{0b10011111, 0b00010001, 0b11110101, 0b01010101}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x01, script.OpRSHIFT, []byte{0b01001111, 0b10001000, 0b11111010, 0b10101010}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x02, script.OpRSHIFT, []byte{0b00100111, 0b11000100, 0b01111101, 0b01010101}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x03, script.OpRSHIFT, []byte{0b00010011, 0b11100010, 0b00111110, 0b10101010}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x04, script.OpRSHIFT, []byte{0b00001001, 0b11110001, 0b00011111, 0b01010101}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x05, script.OpRSHIFT, []byte{0b00000100, 0b11111000, 0b10001111, 0b10101010}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x06, script.OpRSHIFT, []byte{0b00000010, 0b01111100, 0b01000111, 0b11010101}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x07, script.OpRSHIFT, []byte{0b00000001, 0b00111110, 0b00100011, 0b11101010}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x08, script.OpRSHIFT, []byte{0b00000000, 0b10011111, 0b00010001, 0b11110101}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x09, script.OpRSHIFT, []byte{0b00000000, 0b01001111, 0b10001000, 0b11111010}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x0A, script.OpRSHIFT, []byte{0b00000000, 0b00100111, 0b11000100, 0b01111101}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x0B, script.OpRSHIFT, []byte{0b00000000, 0b00010011, 0b11100010, 0b00111110}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x0C, script.OpRSHIFT, []byte{0b00000000, 0b00001001, 0b11110001, 0b00011111}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x0D, script.OpRSHIFT, []byte{0b00000000, 0b00000100, 0b11111000, 0b10001111}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x0E, script.OpRSHIFT, []byte{0b00000000, 0b00000010, 0b01111100, 0b01000111}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x0F, script.OpRSHIFT, []byte{0b00000000, 0b00000001, 0b00111110, 0b00100011}},

		{"", []byte{}, 0, script.OpLSHIFT, []byte{}},
		{"", []byte{}, 0x01, script.OpLSHIFT, []byte{}},
		{"", []byte{}, 0x02, script.OpLSHIFT, []byte{}},
		{"", []byte{}, 0x07, script.OpLSHIFT, []byte{}},
		{"", []byte{}, 0x08, script.OpLSHIFT, []byte{}},
		{"", []byte{}, 0x09, script.OpLSHIFT, []byte{}},
		{"", []byte{}, 0x0F, script.OpLSHIFT, []byte{}},
		{"", []byte{}, 0x10, script.OpLSHIFT, []byte{}},
		{"", []byte{}, 0x11, script.OpLSHIFT, []byte{}},

		{"", []byte{0xFF}, 0, script.OpLSHIFT, []byte{0b11111111}},
		{"", []byte{0xFF}, 0x01, script.OpLSHIFT, []byte{0b11111110}},
		{"", []byte{0xFF}, 0x02, script.OpLSHIFT, []byte{0b11111100}},
		{"", []byte{0xFF}, 0x03, script.OpLSHIFT, []byte{0b11111000}},
		{"", []byte{0xFF}, 0x04, script.OpLSHIFT, []byte{0b11110000}},
		{"", []byte{0xFF}, 0x05, script.OpLSHIFT, []byte{0b11100000}},
		{"", []byte{0xFF}, 0x06, script.OpLSHIFT, []byte{0b11000000}},
		{"", []byte{0xFF}, 0x07, script.OpLSHIFT, []byte{0b10000000}},
		{"", []byte{0xFF}, 0x08, script.OpLSHIFT, []byte{0b00000000}},

		{"", []byte{0xFF}, 0x01, script.OpLSHIFT, []byte{0xFE}},
		{"", []byte{0xFF}, 0x02, script.OpLSHIFT, []byte{0xFC}},
		{"", []byte{0xFF}, 0x03, script.OpLSHIFT, []byte{0xF8}},
		{"", []byte{0xFF}, 0x04, script.OpLSHIFT, []byte{0xF0}},
		{"", []byte{0xFF}, 0x05, script.OpLSHIFT, []byte{0xE0}},
		{"", []byte{0xFF}, 0x06, script.OpLSHIFT, []byte{0xC0}},
		{"", []byte{0xFF}, 0x07, script.OpLSHIFT, []byte{0x80}},

		// bitpattern, not a number so not reduced to zero bytes
		{"", []byte{0xFF}, 0x08, script.OpLSHIFT, []byte{0x00}},

		// shift single bit over byte boundary
		{"", []byte{0x00, 0x80}, 0x01, script.OpLSHIFT, []byte{0x01, 0x00}},
		{"", []byte{0x00, 0x80, 0x00}, 0x01, script.OpLSHIFT, []byte{0x01, 0x00, 0x00}},
		{"", []byte{0x00, 0x00, 0x80}, 0x01, script.OpLSHIFT, []byte{0x00, 0x01, 0x00}},
		{"", []byte{0x80, 0x00, 0x00}, 0x01, script.OpLSHIFT, []byte{0x00, 0x00, 0x00}},

		// []byte{0x9F, 0x11, 0xF5, 0x55} is a sequence of bytes that is equal to the bit pattern
		// "1001 1111 0001 0001 1111 0101 0101 0101"
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0, script.OpLSHIFT, []byte{0b10011111, 0b00010001, 0b11110101, 0b01010101}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x01, script.OpLSHIFT, []byte{0b00111110, 0b00100011, 0b11101010, 0b10101010}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x02, script.OpLSHIFT, []byte{0b01111100, 0b01000111, 0b11010101, 0b01010100}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x03, script.OpLSHIFT, []byte{0b11111000, 0b10001111, 0b10101010, 0b10101000}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x04, script.OpLSHIFT, []byte{0b11110001, 0b00011111, 0b01010101, 0b01010000}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x05, script.OpLSHIFT, []byte{0b11100010, 0b00111110, 0b10101010, 0b10100000}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x06, script.OpLSHIFT, []byte{0b11000100, 0b01111101, 0b01010101, 0b01000000}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x07, script.OpLSHIFT, []byte{0b10001000, 0b11111010, 0b10101010, 0b10000000}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x08, script.OpLSHIFT, []byte{0b00010001, 0b11110101, 0b01010101, 0b00000000}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x09, script.OpLSHIFT, []byte{0b00100011, 0b11101010, 0b10101010, 0b00000000}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x0A, script.OpLSHIFT, []byte{0b01000111, 0b11010101, 0b01010100, 0b00000000}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x0B, script.OpLSHIFT, []byte{0b10001111, 0b10101010, 0b10101000, 0b00000000}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x0C, script.OpLSHIFT, []byte{0b00011111, 0b01010101, 0b01010000, 0b00000000}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x0D, script.OpLSHIFT, []byte{0b00111110, 0b10101010, 0b10100000, 0b00000000}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x0E, script.OpLSHIFT, []byte{0b01111101, 0b01010101, 0b01000000, 0b00000000}},
		{"", []byte{0x9F, 0x11, 0xF5, 0x55}, 0x0F, script.OpLSHIFT, []byte{0b11111010, 0b10101010, 0b10000000, 0b00000000}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new thread with necessary configuration
			thread := &thread{
				dstack:       newStack(&afterGenesisConfig{}, false),
				afterGenesis: true,                  // Set this according to your needs
				cfg:          &afterGenesisConfig{}, // Use appropriate config
				scriptParser: &DefaultOpcodeParser{},
			}

			// Push the initial value and shift amount onto the stack
			thread.dstack.PushByteArray(tt.initial)

			thread.dstack.PushInt(&ScriptNumber{
				Val:          big.NewInt(tt.shift),
				AfterGenesis: thread.afterGenesis,
			})

			// Create a ParsedOpcode for the shift operation
			pop := ParsedOpcode{op: opcodeArray[tt.op], Data: nil}

			// Execute the opcode
			var opErr error
			if tt.op == script.OpLSHIFT {
				opErr = opcodeLShift(&pop, thread)
			} else {
				opErr = opcodeRShift(&pop, thread)
			}

			// Check for errors
			require.NoError(t, opErr)

			// Check the result
			result, err := thread.dstack.PopByteArray()
			require.NoError(t, err)
			require.Equal(t, tt.expected, result)
		})
	}
}
