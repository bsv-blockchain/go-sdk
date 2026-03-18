package script_test

import (
	"encoding/binary"
	"testing"

	script "github.com/bsv-blockchain/go-sdk/script"
	"github.com/stretchr/testify/require"
)

// TestScript_Bytes verifies that Bytes returns the underlying byte slice.
func TestScript_Bytes(t *testing.T) {
	t.Parallel()

	t.Run("non-empty script", func(t *testing.T) {
		s, err := script.NewFromHex("76a914e2a623699e81b291c0327f408fea765d534baa2a88ac")
		require.NoError(t, err)
		b := s.Bytes()
		require.NotNil(t, b)
		require.Equal(t, []byte(*s), b)
		require.Len(t, b, 25)
	})

	t.Run("empty script", func(t *testing.T) {
		s := script.NewFromBytes([]byte{})
		b := s.Bytes()
		require.NotNil(t, b)
		require.Empty(t, b)
	})

	t.Run("round-trip: bytes matches original hex", func(t *testing.T) {
		hexStr := "76a914e2a623699e81b291c0327f408fea765d534baa2a88ac"
		s, err := script.NewFromHex(hexStr)
		require.NoError(t, err)
		require.Equal(t, hexStr, s.String())
		require.Equal(t, []byte(*s), s.Bytes())
	})
}

// TestScript_Slice verifies that Slice returns the correct sub-slice.
func TestScript_Slice(t *testing.T) {
	t.Parallel()

	t.Run("slice full range", func(t *testing.T) {
		s, err := script.NewFromHex("76a914e2a623699e81b291c0327f408fea765d534baa2a88ac")
		require.NoError(t, err)
		sliced := s.Slice(0, uint64(len(*s)))
		require.Equal(t, s.Bytes(), sliced.Bytes())
	})

	t.Run("slice first byte", func(t *testing.T) {
		s, err := script.NewFromHex("76a914")
		require.NoError(t, err)
		sliced := s.Slice(0, 1)
		require.Equal(t, []byte{0x76}, sliced.Bytes())
	})

	t.Run("slice middle portion", func(t *testing.T) {
		// P2PKH: 76 a9 14 <20-byte-hash> 88 ac
		s, err := script.NewFromHex("76a914e2a623699e81b291c0327f408fea765d534baa2a88ac")
		require.NoError(t, err)
		// bytes 3..23 = the 20-byte hash
		sliced := s.Slice(3, 23)
		require.Len(t, sliced.Bytes(), 20)
	})

	t.Run("slice single byte at end", func(t *testing.T) {
		s, err := script.NewFromHex("76a914e2a623699e81b291c0327f408fea765d534baa2a88ac")
		require.NoError(t, err)
		last := uint64(len(*s))
		sliced := s.Slice(last-1, last)
		require.Equal(t, []byte{script.OpCHECKSIG}, sliced.Bytes())
	})
}

// TestScript_Address verifies Address extraction from P2PKH scripts.
func TestScript_Address(t *testing.T) {
	t.Parallel()

	t.Run("valid P2PKH returns address", func(t *testing.T) {
		// Known P2PKH script for address 1E7ucTTWRTahCyViPhxSMor2pj4VGQdFMr
		s, err := script.NewFromHex("76a9148fe80c75c9560e8b56ed64ea3c26e18d2c52211b88ac")
		require.NoError(t, err)
		addr, err := s.Address()
		require.NoError(t, err)
		require.NotNil(t, addr)
		require.Equal(t, "1E7ucTTWRTahCyViPhxSMor2pj4VGQdFMr", addr.AddressString)
	})

	t.Run("non-P2PKH script returns error", func(t *testing.T) {
		// OP_RETURN data script
		s, err := script.NewFromHex("6a04deadbeef")
		require.NoError(t, err)
		addr, err := s.Address()
		require.Error(t, err)
		require.Nil(t, addr)
	})

	t.Run("empty script returns error", func(t *testing.T) {
		s := script.NewFromBytes([]byte{})
		addr, err := s.Address()
		require.Error(t, err)
		require.Nil(t, addr)
	})

	t.Run("P2SH script returns error", func(t *testing.T) {
		// OP_HASH160 <20 bytes> OP_EQUAL
		hash := make([]byte, 20)
		b := []byte{script.OpHASH160, script.OpDATA20}
		b = append(b, hash...)
		b = append(b, script.OpEQUAL)
		s := script.NewFromBytes(b)
		addr, err := s.Address()
		require.Error(t, err)
		require.Nil(t, addr)
	})
}

// TestScript_IsMultiSigOut verifies multisig output detection.
func TestScript_IsMultiSigOut(t *testing.T) {
	t.Parallel()

	// Build a valid 1-of-2 multisig output script: OP_1 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
	buildMultiSig := func(t *testing.T, m, n int, pubkeys [][]byte) *script.Script {
		t.Helper()
		s := script.NewFromBytes([]byte{})
		// OP_m (OP_ONE = 0x51, so m-of-n uses 0x50+m)
		require.NoError(t, s.AppendOpcodes(byte(0x50+m)))
		for _, pk := range pubkeys {
			require.NoError(t, s.AppendPushData(pk))
		}
		// OP_n
		require.NoError(t, s.AppendOpcodes(byte(0x50+n)))
		require.NoError(t, s.AppendOpcodes(script.OpCHECKMULTISIG))
		return s
	}

	t.Run("valid 1-of-2 multisig", func(t *testing.T) {
		// Compressed pubkeys (33 bytes each)
		pk1 := make([]byte, 33)
		pk1[0] = 0x02
		pk2 := make([]byte, 33)
		pk2[0] = 0x03
		s := buildMultiSig(t, 1, 2, [][]byte{pk1, pk2})
		require.True(t, s.IsMultiSigOut())
	})

	t.Run("valid 2-of-3 multisig", func(t *testing.T) {
		pk := func(prefix byte) []byte {
			b := make([]byte, 33)
			b[0] = prefix
			return b
		}
		s := buildMultiSig(t, 2, 3, [][]byte{pk(0x02), pk(0x03), pk(0x02)})
		require.True(t, s.IsMultiSigOut())
	})

	t.Run("non-multisig P2PKH returns false", func(t *testing.T) {
		s, err := script.NewFromHex("76a914e2a623699e81b291c0327f408fea765d534baa2a88ac")
		require.NoError(t, err)
		require.False(t, s.IsMultiSigOut())
	})

	t.Run("empty script returns false", func(t *testing.T) {
		s := script.NewFromBytes([]byte{})
		require.False(t, s.IsMultiSigOut())
	})

	t.Run("too few parts returns false", func(t *testing.T) {
		// Only OP_1 OP_CHECKMULTISIG — no pubkey data between
		s := script.NewFromBytes([]byte{script.OpONE, script.OpCHECKMULTISIG})
		require.False(t, s.IsMultiSigOut())
	})

	t.Run("first op not small int returns false", func(t *testing.T) {
		// OP_DUP <pubkey> OP_1 OP_CHECKMULTISIG — first op is OP_DUP (not small int)
		pk := make([]byte, 33)
		pk[0] = 0x02
		s := script.NewFromBytes([]byte{script.OpDUP})
		require.NoError(t, s.AppendPushData(pk))
		require.NoError(t, s.AppendOpcodes(script.OpONE, script.OpCHECKMULTISIG))
		require.False(t, s.IsMultiSigOut())
	})

	t.Run("data part with zero length returns false", func(t *testing.T) {
		// OP_1 OP_NOP OP_1 OP_CHECKMULTISIG — middle part has no data
		s := script.NewFromBytes([]byte{script.OpONE, script.OpNOP, script.OpONE, script.OpCHECKMULTISIG})
		require.False(t, s.IsMultiSigOut())
	})
}

// TestReadOp_ExtraCases exercises the uncovered branches of ReadOp.
func TestReadOp_ExtraCases(t *testing.T) {
	t.Parallel()

	t.Run("OpPUSHDATA1 valid", func(t *testing.T) {
		data := []byte("hello")
		b := []byte{script.OpPUSHDATA1, byte(len(data))}
		b = append(b, data...)
		s := script.Script(b)
		pos := 0
		op, err := s.ReadOp(&pos)
		require.NoError(t, err)
		require.Equal(t, script.OpPUSHDATA1, op.Op)
		require.Equal(t, data, op.Data)
		require.Equal(t, len(b), pos)
	})

	t.Run("OpPUSHDATA1 missing length byte", func(t *testing.T) {
		b := []byte{script.OpPUSHDATA1} // no length byte
		s := script.Script(b)
		pos := 0
		_, err := s.ReadOp(&pos)
		require.Error(t, err)
	})

	t.Run("OpPUSHDATA1 data too small", func(t *testing.T) {
		b := []byte{script.OpPUSHDATA1, 10, 0x01, 0x02} // says 10 bytes but only 2
		s := script.Script(b)
		pos := 0
		_, err := s.ReadOp(&pos)
		require.Error(t, err)
	})

	t.Run("OpPUSHDATA2 valid", func(t *testing.T) {
		data := make([]byte, 300)
		for i := range data {
			data[i] = byte(i)
		}
		lenBuf := make([]byte, 2)
		binary.LittleEndian.PutUint16(lenBuf, uint16(len(data)))
		b := []byte{script.OpPUSHDATA2}
		b = append(b, lenBuf...)
		b = append(b, data...)
		s := script.Script(b)
		pos := 0
		op, err := s.ReadOp(&pos)
		require.NoError(t, err)
		require.Equal(t, script.OpPUSHDATA2, op.Op)
		require.Equal(t, data, op.Data)
	})

	t.Run("OpPUSHDATA2 header too small", func(t *testing.T) {
		b := []byte{script.OpPUSHDATA2, 0x01} // needs 3 bytes minimum
		s := script.Script(b)
		pos := 0
		_, err := s.ReadOp(&pos)
		require.Error(t, err)
	})

	t.Run("OpPUSHDATA2 data too small", func(t *testing.T) {
		lenBuf := make([]byte, 2)
		binary.LittleEndian.PutUint16(lenBuf, 100)
		b := []byte{script.OpPUSHDATA2}
		b = append(b, lenBuf...)
		b = append(b, make([]byte, 5)...) // only 5 bytes, needs 100
		s := script.Script(b)
		pos := 0
		_, err := s.ReadOp(&pos)
		require.Error(t, err)
	})

	t.Run("OpPUSHDATA4 valid", func(t *testing.T) {
		data := make([]byte, 10)
		lenBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBuf, uint32(len(data)))
		b := []byte{script.OpPUSHDATA4}
		b = append(b, lenBuf...)
		b = append(b, data...)
		s := script.Script(b)
		pos := 0
		op, err := s.ReadOp(&pos)
		require.NoError(t, err)
		require.Equal(t, script.OpPUSHDATA4, op.Op)
		require.Equal(t, data, op.Data)
	})

	t.Run("OpPUSHDATA4 header too small", func(t *testing.T) {
		b := []byte{script.OpPUSHDATA4, 0x01, 0x02, 0x03} // needs 5 bytes minimum
		s := script.Script(b)
		pos := 0
		_, err := s.ReadOp(&pos)
		require.Error(t, err)
	})

	t.Run("OpPUSHDATA4 data too small", func(t *testing.T) {
		lenBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBuf, 500)
		b := []byte{script.OpPUSHDATA4}
		b = append(b, lenBuf...)
		b = append(b, make([]byte, 5)...) // only 5 bytes, needs 500
		s := script.Script(b)
		pos := 0
		_, err := s.ReadOp(&pos)
		require.Error(t, err)
	})

	t.Run("op data inline (OpDATA1 range) valid", func(t *testing.T) {
		// OpDATA3 = 0x03, followed by 3 bytes of data
		b := []byte{script.OpDATA3, 0xAA, 0xBB, 0xCC}
		s := script.Script(b)
		pos := 0
		op, err := s.ReadOp(&pos)
		require.NoError(t, err)
		require.Equal(t, script.OpDATA3, op.Op)
		require.Equal(t, []byte{0xAA, 0xBB, 0xCC}, op.Data)
	})

	t.Run("op data inline truncated", func(t *testing.T) {
		// OpDATA5 = 0x05, but only 2 bytes of data follow
		b := []byte{script.OpDATA5, 0x01, 0x02}
		s := script.Script(b)
		pos := 0
		_, err := s.ReadOp(&pos)
		require.Error(t, err)
	})

	t.Run("simple opcode (no data)", func(t *testing.T) {
		b := []byte{script.OpDUP}
		s := script.Script(b)
		pos := 0
		op, err := s.ReadOp(&pos)
		require.NoError(t, err)
		require.Equal(t, script.OpDUP, op.Op)
		require.Nil(t, op.Data)
		require.Equal(t, 1, pos)
	})

	t.Run("out of range pos", func(t *testing.T) {
		b := []byte{script.OpDUP}
		s := script.Script(b)
		pos := 5
		_, err := s.ReadOp(&pos)
		require.Error(t, err)
	})
}

// TestParseOps exercises ParseOps.
func TestParseOps(t *testing.T) {
	t.Parallel()

	t.Run("valid P2PKH script", func(t *testing.T) {
		s, err := script.NewFromHex("76a914e2a623699e81b291c0327f408fea765d534baa2a88ac")
		require.NoError(t, err)
		ops, err := s.ParseOps()
		require.NoError(t, err)
		require.Len(t, ops, 5) // OP_DUP OP_HASH160 <data20> OP_EQUALVERIFY OP_CHECKSIG
	})

	t.Run("empty script", func(t *testing.T) {
		s := script.NewFromBytes([]byte{})
		ops, err := s.ParseOps()
		require.NoError(t, err)
		require.Empty(t, ops)
	})

	t.Run("error on truncated script", func(t *testing.T) {
		// OpDATA5 followed by only 2 bytes (should be 5)
		b := []byte{script.OpDATA5, 0x01, 0x02}
		s := script.Script(b)
		ops, err := s.ParseOps()
		require.Error(t, err)
		require.Nil(t, ops)
	})

	t.Run("multiple push data ops", func(t *testing.T) {
		s := script.NewFromBytes([]byte{})
		require.NoError(t, s.AppendPushData([]byte("foo")))
		require.NoError(t, s.AppendPushData([]byte("bar")))
		ops, err := s.ParseOps()
		require.NoError(t, err)
		require.Len(t, ops, 2)
		require.Equal(t, []byte("foo"), ops[0].Data)
		require.Equal(t, []byte("bar"), ops[1].Data)
	})
}

// TestNewScriptFromScriptOps exercises NewScriptFromScriptOps.
func TestNewScriptFromScriptOps(t *testing.T) {
	t.Parallel()

	t.Run("round-trip P2PKH", func(t *testing.T) {
		orig, err := script.NewFromHex("76a914e2a623699e81b291c0327f408fea765d534baa2a88ac")
		require.NoError(t, err)

		ops, err := orig.ParseOps()
		require.NoError(t, err)

		rebuilt, err := script.NewScriptFromScriptOps(ops)
		require.NoError(t, err)
		require.Equal(t, orig.Bytes(), rebuilt.Bytes())
	})

	t.Run("empty parts produces empty script", func(t *testing.T) {
		s, err := script.NewScriptFromScriptOps([]*script.ScriptChunk{})
		require.NoError(t, err)
		require.NotNil(t, s)
		require.Empty(t, s.Bytes())
	})

	t.Run("opcodes only", func(t *testing.T) {
		parts := []*script.ScriptChunk{
			{Op: script.OpDUP},
			{Op: script.OpHASH160},
			{Op: script.OpEQUALVERIFY},
			{Op: script.OpCHECKSIG},
		}
		s, err := script.NewScriptFromScriptOps(parts)
		require.NoError(t, err)
		require.Equal(t, []byte{script.OpDUP, script.OpHASH160, script.OpEQUALVERIFY, script.OpCHECKSIG}, s.Bytes())
	})

	t.Run("OpPUSHDATA1 chunk", func(t *testing.T) {
		data := make([]byte, 100) // > 75, triggers PUSHDATA1
		for i := range data {
			data[i] = byte(i)
		}
		parts := []*script.ScriptChunk{
			{Op: script.OpPUSHDATA1, Data: data},
		}
		s, err := script.NewScriptFromScriptOps(parts)
		require.NoError(t, err)
		require.NotNil(t, s)
		// Verify the data round-trips
		ops, err := s.ParseOps()
		require.NoError(t, err)
		require.Len(t, ops, 1)
		require.Equal(t, data, ops[0].Data)
	})

	t.Run("OpPUSHDATA2 chunk", func(t *testing.T) {
		data := make([]byte, 300) // > 255, triggers PUSHDATA2
		parts := []*script.ScriptChunk{
			{Op: script.OpPUSHDATA2, Data: data},
		}
		s, err := script.NewScriptFromScriptOps(parts)
		require.NoError(t, err)
		require.NotNil(t, s)
		ops, err := s.ParseOps()
		require.NoError(t, err)
		require.Len(t, ops, 1)
		require.Equal(t, data, ops[0].Data)
	})

	t.Run("OpPUSHDATA4 chunk", func(t *testing.T) {
		data := make([]byte, 70000) // > 65535, triggers PUSHDATA4
		parts := []*script.ScriptChunk{
			{Op: script.OpPUSHDATA4, Data: data},
		}
		s, err := script.NewScriptFromScriptOps(parts)
		require.NoError(t, err)
		require.NotNil(t, s)
		ops, err := s.ParseOps()
		require.NoError(t, err)
		require.Len(t, ops, 1)
		require.Len(t, ops[0].Data, 70000)
	})

	t.Run("OpRETURN with data appended", func(t *testing.T) {
		payload := []byte("hello world")
		parts := []*script.ScriptChunk{
			{Op: script.OpRETURN, Data: payload},
		}
		s, err := script.NewScriptFromScriptOps(parts)
		require.NoError(t, err)
		require.NotNil(t, s)
		// First byte should be OP_RETURN, followed by payload
		b := s.Bytes()
		require.Equal(t, script.OpRETURN, b[0])
		require.Equal(t, payload, b[1:])
	})

	t.Run("OpRETURN without data", func(t *testing.T) {
		parts := []*script.ScriptChunk{
			{Op: script.OpRETURN},
		}
		s, err := script.NewScriptFromScriptOps(parts)
		require.NoError(t, err)
		require.Equal(t, []byte{script.OpRETURN}, s.Bytes())
	})
}
