package script_test

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/script"
)

// refChunk is one chunk as the TypeScript SDK's Script.#parseChunks reads it.
type refChunk struct {
	op   byte
	data []byte
}

// refParseChunks follows ts-stack's Script.#parseChunks for scripts whose pushes
// are complete: an OP_RETURN takes the rest of the script as data only when the
// IF depth is exactly 0; OP_IF/NOTIF/VERIF/VERNOTIF add one and OP_ENDIF
// subtracts one, with no floor.
func refParseChunks(b []byte) []refChunk {
	var out []refChunk
	depth := 0
	for pos := 0; pos < len(b); {
		op := b[pos]
		pos++
		if op == script.OpRETURN && depth == 0 {
			out = append(out, refChunk{op: op, data: b[pos:]})
			break
		}
		switch op {
		case script.OpIF, script.OpNOTIF, script.OpVERIF, script.OpVERNOTIF:
			depth++
		case script.OpENDIF:
			depth--
		}
		if op > 0 && op <= script.OpPUSHDATA4 {
			// The generators below only emit direct pushes (1 to 75 bytes).
			end := pos + int(op)
			out = append(out, refChunk{op: op, data: b[pos:end]})
			pos = end
		} else {
			out = append(out, refChunk{op: op})
		}
	}
	return out
}

func decodeHex(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	require.NoError(t, err)
	return b
}

// The shapes of go-sdk issue 417 whose OP_RETURN sits at a negative IF depth, and
// two controls that already agreed. The counts are the TypeScript reference's.
func TestDecodeScriptIfDepth(t *testing.T) {
	cases := []struct {
		name, hex string
		chunks    int
	}{
		{"stray ENDIF then RETURN", "686a51", 3},
		{"stray ENDIF, RETURN, push", "686a0568656c6c6f", 3},
		{"two stray ENDIFs", "68686a51", 4},
		{"IF, two ENDIFs, RETURN, push", "6368686a0568656c6c6f", 5},
		{"OP_1 IF ENDIF ENDIF RETURN OP_1", "516368686a51", 6},
		{"five-deep mix", "516351636868686a51", 9},
		{"control: ENDIF IF RETURN OP_1 ENDIF returns to depth 0", "68636a5168", 3},
		{"control: RETURN at depth 0 takes the rest as data", "6a51", 1},
		{"control: RETURN inside an IF is an opcode", "63516a68", 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chunks, err := script.DecodeScript(decodeHex(t, tc.hex))
			require.NoError(t, err)
			require.Len(t, chunks, tc.chunks)
		})
	}

	t.Run("the RETURN after a stray ENDIF is a bare opcode, not a data carrier", func(t *testing.T) {
		chunks, err := script.DecodeScript(decodeHex(t, "686a51"))
		require.NoError(t, err)
		require.Equal(t, script.OpRETURN, chunks[1].Op)
		require.Empty(t, chunks[1].Data)
		require.Equal(t, script.Op1, chunks[2].Op)
	})
}

// DecodeScript must read the reference's chunks on every script built from IF
// openers, ENDIF, ELSE, RETURN and complete pushes, so a stray ENDIF cannot change
// which OP_RETURN folds. The generator is seeded, so the run is deterministic.
func TestDecodeScriptMatchesReferenceChunking(t *testing.T) {
	rng := rand.New(rand.NewSource(417)) //nolint:gosec // G404 -- a fixed seed keeps the generated scripts deterministic
	alphabet := [][]byte{
		{script.OpIF},
		{script.OpNOTIF},
		{script.OpENDIF},
		{script.OpENDIF},
		{script.OpELSE},
		{script.OpRETURN},
		{script.Op1},
		{script.Op0},
		{script.OpDUP},
		{0x03, 0xaa, 0xbb, 0xcc},
		{0x05, 'h', 'e', 'l', 'l', 'o'},
	}
	negativeDepthReturns := 0
	for n := 0; n < 20000; n++ {
		var s []byte
		for k := rng.Intn(12) + 1; k > 0; k-- {
			s = append(s, alphabet[rng.Intn(len(alphabet))]...)
		}
		want := refParseChunks(s)
		got, err := script.DecodeScript(s)
		require.NoError(t, err, "script %x", s)
		require.Len(t, got, len(want), "script %x", s)
		for i := range want {
			require.Equal(t, want[i].op, got[i].Op, "script %x chunk %d", s, i)
			require.True(t, bytes.Equal(want[i].data, got[i].Data), "script %x chunk %d: data %x, want %x", s, i, got[i].Data, want[i].data)
		}
		// Count scripts that reach an OP_RETURN below depth 0, so the run cannot pass without them.
		depth := 0
		for pos := 0; pos < len(s); {
			op := s[pos]
			pos++
			if op == script.OpRETURN && depth < 0 {
				negativeDepthReturns++
			}
			switch {
			case op == script.OpIF || op == script.OpNOTIF:
				depth++
			case op == script.OpENDIF:
				depth--
			case op > 0 && op <= script.OpPUSHDATA4:
				pos += int(op)
			}
		}
	}
	require.Positive(t, negativeDepthReturns, "no OP_RETURN at a negative depth was generated")
}
