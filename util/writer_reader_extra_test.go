package util_test

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/stretchr/testify/require"
)

const (
	subTestNonEmptyString    = "non-empty string"
	subTestInvalidHexError   = "invalid hex returns error"
	subTestNilOnPriorError   = "nil on prior error"
	subTestEmptyOnPriorError = "empty on prior error"
)

// ---------------------------------------------------------------------------
// HTTPError
// ---------------------------------------------------------------------------

func TestHTTPErrorError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		code     int
		err      error
		expected string
	}{
		{"404 Not Found", 404, errors.New("Not Found"), "404-Not Found"},
		{"500 Internal Server Error", 500, errors.New("Internal Server Error"), "500-Internal Server Error"},
		{"200 OK", 200, errors.New("OK"), "200-OK"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &util.HTTPError{StatusCode: tt.code, Err: tt.err}
			require.Equal(t, tt.expected, e.Error())
		})
	}
}

// ---------------------------------------------------------------------------
// Writer helpers
// ---------------------------------------------------------------------------

func TestWriterWriteBytesReverse(t *testing.T) {
	t.Parallel()

	w := util.NewWriter()
	w.WriteBytesReverse([]byte{0x01, 0x02, 0x03, 0x04})
	require.Equal(t, []byte{0x04, 0x03, 0x02, 0x01}, w.Buf)
}

func TestWriterWriteBytesReverseEmpty(t *testing.T) {
	t.Parallel()

	w := util.NewWriter()
	w.WriteBytesReverse([]byte{})
	require.Empty(t, w.Buf)
}

func TestWriterWriteIntBytes(t *testing.T) {
	t.Parallel()

	w := util.NewWriter()
	w.WriteIntBytes([]byte{0xAA, 0xBB})
	// varint(2) + 2 bytes
	require.Equal(t, []byte{0x02, 0xAA, 0xBB}, w.Buf)
}

func TestWriterWriteIntBytesOptional(t *testing.T) {
	t.Parallel()

	t.Run("non-empty writes length prefix and data", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteIntBytesOptional([]byte{0x01, 0x02})
		require.Equal(t, []byte{0x02, 0x01, 0x02}, w.Buf)
	})

	t.Run("empty writes negative-one varint", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteIntBytesOptional(nil)
		// NegativeOne is math.MaxUint64 = 0xFF * 9 bytes
		vi := util.VarInt(math.MaxUint64).Bytes()
		require.Equal(t, vi, w.Buf)
	})
}

func TestWriterWriteVarIntOptional(t *testing.T) {
	t.Parallel()

	t.Run("nil writes negative-one", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteVarIntOptional(nil)
		expected := util.VarInt(math.MaxUint64).Bytes()
		require.Equal(t, expected, w.Buf)
	})

	t.Run("value writes varint", func(t *testing.T) {
		w := util.NewWriter()
		v := uint64(42)
		w.WriteVarIntOptional(&v)
		require.Equal(t, []byte{0x2A}, w.Buf)
	})
}

func TestWriterWriteNegativeOne(t *testing.T) {
	t.Parallel()

	w := util.NewWriter()
	w.WriteNegativeOne()
	expected := util.VarInt(math.MaxUint64).Bytes()
	require.Equal(t, expected, w.Buf)
}

func TestWriterWriteNegativeOneByte(t *testing.T) {
	t.Parallel()

	w := util.NewWriter()
	w.WriteNegativeOneByte()
	require.Equal(t, []byte{0xFF}, w.Buf)
}

func TestIsNegativeOne(t *testing.T) {
	t.Parallel()

	require.True(t, util.IsNegativeOne(math.MaxUint64))
	require.False(t, util.IsNegativeOne(0))
	require.False(t, util.IsNegativeOne(1))
}

func TestIsNegativeOneByte(t *testing.T) {
	t.Parallel()

	require.True(t, util.IsNegativeOneByte(0xFF))
	require.False(t, util.IsNegativeOneByte(0x00))
	require.False(t, util.IsNegativeOneByte(0xFE))
}

func TestWriterWriteString(t *testing.T) {
	t.Parallel()

	w := util.NewWriter()
	w.WriteString("hi")
	// varint(2) + "hi"
	require.Equal(t, []byte{0x02, 'h', 'i'}, w.Buf)
}

func TestWriterWriteOptionalString(t *testing.T) {
	t.Parallel()

	t.Run(subTestNonEmptyString, func(t *testing.T) {
		w := util.NewWriter()
		w.WriteOptionalString("ab")
		require.Equal(t, []byte{0x02, 'a', 'b'}, w.Buf)
	})

	t.Run("empty string writes negative-one", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteOptionalString("")
		expected := util.VarInt(math.MaxUint64).Bytes()
		require.Equal(t, expected, w.Buf)
	})
}

func TestWriterWriteOptionalFromHex(t *testing.T) {
	t.Parallel()

	t.Run("non-empty hex", func(t *testing.T) {
		w := util.NewWriter()
		err := w.WriteOptionalFromHex("0102")
		require.NoError(t, err)
		require.Equal(t, []byte{0x02, 0x01, 0x02}, w.Buf)
	})

	t.Run("empty writes negative-one", func(t *testing.T) {
		w := util.NewWriter()
		err := w.WriteOptionalFromHex("")
		require.NoError(t, err)
		expected := util.VarInt(math.MaxUint64).Bytes()
		require.Equal(t, expected, w.Buf)
	})

	t.Run(subTestInvalidHexError, func(t *testing.T) {
		w := util.NewWriter()
		err := w.WriteOptionalFromHex("XY")
		require.Error(t, err)
	})
}

func TestWriterWriteRemainingFromHex(t *testing.T) {
	t.Parallel()

	t.Run("valid hex", func(t *testing.T) {
		w := util.NewWriter()
		err := w.WriteRemainingFromHex("deadbeef")
		require.NoError(t, err)
		require.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, w.Buf)
	})

	t.Run(subTestInvalidHexError, func(t *testing.T) {
		w := util.NewWriter()
		err := w.WriteRemainingFromHex("GG")
		require.Error(t, err)
	})
}

func TestWriterWriteIntFromHex(t *testing.T) {
	t.Parallel()

	t.Run("valid hex", func(t *testing.T) {
		w := util.NewWriter()
		err := w.WriteIntFromHex("aabb")
		require.NoError(t, err)
		// varint(2) + 0xAA 0xBB
		require.Equal(t, []byte{0x02, 0xAA, 0xBB}, w.Buf)
	})

	t.Run(subTestInvalidHexError, func(t *testing.T) {
		w := util.NewWriter()
		err := w.WriteIntFromHex("ZZ")
		require.Error(t, err)
	})
}

func TestWriterWriteSizeFromHex(t *testing.T) {
	t.Parallel()

	t.Run("correct size", func(t *testing.T) {
		w := util.NewWriter()
		err := w.WriteSizeFromHex("aabb", 2)
		require.NoError(t, err)
		require.Equal(t, []byte{0xAA, 0xBB}, w.Buf)
	})

	t.Run("size mismatch returns error", func(t *testing.T) {
		w := util.NewWriter()
		err := w.WriteSizeFromHex("aabb", 3)
		require.Error(t, err)
		require.Contains(t, err.Error(), "bytes long")
	})

	t.Run(subTestInvalidHexError, func(t *testing.T) {
		w := util.NewWriter()
		err := w.WriteSizeFromHex("ZZ", 1)
		require.Error(t, err)
	})
}

func TestWriterWriteIntFromBase64(t *testing.T) {
	t.Parallel()

	t.Run("valid base64", func(t *testing.T) {
		data := []byte{0x01, 0x02}
		encoded := base64.StdEncoding.EncodeToString(data)
		w := util.NewWriter()
		err := w.WriteIntFromBase64(encoded)
		require.NoError(t, err)
		require.Equal(t, []byte{0x02, 0x01, 0x02}, w.Buf)
	})

	t.Run("invalid base64 returns error", func(t *testing.T) {
		w := util.NewWriter()
		err := w.WriteIntFromBase64("!!")
		require.Error(t, err)
	})
}

func TestWriterWriteSizeFromBase64(t *testing.T) {
	t.Parallel()

	t.Run("correct size", func(t *testing.T) {
		data := []byte{0x01, 0x02}
		encoded := base64.StdEncoding.EncodeToString(data)
		w := util.NewWriter()
		err := w.WriteSizeFromBase64(encoded, 2)
		require.NoError(t, err)
		require.Equal(t, []byte{0x01, 0x02}, w.Buf)
	})

	t.Run("size mismatch returns error", func(t *testing.T) {
		data := []byte{0x01, 0x02}
		encoded := base64.StdEncoding.EncodeToString(data)
		w := util.NewWriter()
		err := w.WriteSizeFromBase64(encoded, 3)
		require.Error(t, err)
	})

	t.Run("invalid base64 returns error", func(t *testing.T) {
		w := util.NewWriter()
		err := w.WriteSizeFromBase64("!!", 1)
		require.Error(t, err)
	})
}

func TestWriterWriteOptionalBytes(t *testing.T) {
	t.Parallel()

	t.Run("no options non-empty", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteOptionalBytes([]byte{0x01, 0x02})
		require.Equal(t, []byte{0x02, 0x01, 0x02}, w.Buf)
	})

	t.Run("no options empty writes MaxUint64", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteOptionalBytes(nil)
		expected := util.VarInt(math.MaxUint64).Bytes()
		require.Equal(t, expected, w.Buf)
	})

	t.Run("with flag non-empty", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteOptionalBytes([]byte{0xAB}, util.BytesOptionWithFlag)
		// flag=1, varint(1), 0xAB
		require.Equal(t, []byte{0x01, 0x01, 0xAB}, w.Buf)
	})

	t.Run("with flag empty writes 0", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteOptionalBytes(nil, util.BytesOptionWithFlag)
		require.Equal(t, []byte{0x00}, w.Buf)
	})

	t.Run("with TxIdLen skips varint prefix", func(t *testing.T) {
		data := make([]byte, 32)
		w := util.NewWriter()
		w.WriteOptionalBytes(data, util.BytesOptionTxIdLen)
		require.Equal(t, data, w.Buf)
	})

	t.Run("zero if empty option", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteOptionalBytes(nil, util.BytesOptionZeroIfEmpty)
		require.Equal(t, []byte{0x00}, w.Buf)
	})
}

func TestWriterWriteOptionalUint32(t *testing.T) {
	t.Parallel()

	t.Run("non-nil value", func(t *testing.T) {
		w := util.NewWriter()
		v := uint32(100)
		w.WriteOptionalUint32(&v)
		require.Equal(t, []byte{0x64}, w.Buf)
	})

	t.Run("nil writes negative-one", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteOptionalUint32(nil)
		expected := util.VarInt(math.MaxUint64).Bytes()
		require.Equal(t, expected, w.Buf)
	})
}

func TestWriterWriteStringSlice(t *testing.T) {
	t.Parallel()

	t.Run("non-nil slice", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteStringSlice([]string{"a", "b"})
		// varint(2) + encoded "a" + encoded "b"
		require.Greater(t, len(w.Buf), 2)
	})

	t.Run("nil slice writes negative-one", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteStringSlice(nil)
		expected := util.VarInt(math.MaxUint64).Bytes()
		require.Equal(t, expected, w.Buf)
	})
}

func TestWriterWriteOptionalBool(t *testing.T) {
	t.Parallel()

	t.Run("true", func(t *testing.T) {
		w := util.NewWriter()
		b := true
		w.WriteOptionalBool(&b)
		require.Equal(t, []byte{0x01}, w.Buf)
	})

	t.Run("false", func(t *testing.T) {
		w := util.NewWriter()
		b := false
		w.WriteOptionalBool(&b)
		require.Equal(t, []byte{0x00}, w.Buf)
	})

	t.Run("nil writes 0xFF", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteOptionalBool(nil)
		require.Equal(t, []byte{0xFF}, w.Buf)
	})
}

func TestWriterWriteTxidSlice(t *testing.T) {
	t.Parallel()

	t.Run("non-nil slice", func(t *testing.T) {
		txid1, _ := chainhash.NewHashFromHex("0000000000000000000000000000000000000000000000000000000000000001")
		txid2, _ := chainhash.NewHashFromHex("0000000000000000000000000000000000000000000000000000000000000002")
		w := util.NewWriter()
		err := w.WriteTxidSlice([]chainhash.Hash{*txid1, *txid2})
		require.NoError(t, err)
		// varint(2) + 32 + 32 bytes
		require.Len(t, w.Buf, 1+32+32)
	})

	t.Run("nil slice writes MaxUint64", func(t *testing.T) {
		w := util.NewWriter()
		err := w.WriteTxidSlice(nil)
		require.NoError(t, err)
		expected := util.VarInt(math.MaxUint64).Bytes()
		require.Equal(t, expected, w.Buf)
	})
}

func TestWriterWriteStringMap(t *testing.T) {
	t.Parallel()

	w := util.NewWriter()
	w.WriteStringMap(map[string]string{
		"key1": "val1",
		"key2": "val2",
	})
	// Should have varint(2) + encoded pairs
	require.Greater(t, len(w.Buf), 1)
}

// ---------------------------------------------------------------------------
// Reader - uncovered methods
// ---------------------------------------------------------------------------

func TestReaderReadBytesReverse(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		r := util.NewReader([]byte{0x01, 0x02, 0x03, 0x04})
		b, err := r.ReadBytesReverse(4)
		require.NoError(t, err)
		require.Equal(t, []byte{0x04, 0x03, 0x02, 0x01}, b)
	})

	t.Run("past end returns error", func(t *testing.T) {
		r := util.NewReader([]byte{0x01})
		_, err := r.ReadBytesReverse(5)
		require.Error(t, err)
	})
}

func TestReaderReadIntBytes(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		// Write varint(3) + 3 bytes
		w := util.NewWriter()
		w.WriteIntBytes([]byte{0x01, 0x02, 0x03})
		r := util.NewReader(w.Buf)
		b, err := r.ReadIntBytes()
		require.NoError(t, err)
		require.Equal(t, []byte{0x01, 0x02, 0x03}, b)
	})

	t.Run("zero length returns nil", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteVarInt(0)
		r := util.NewReader(w.Buf)
		b, err := r.ReadIntBytes()
		require.NoError(t, err)
		require.Nil(t, b)
	})

	t.Run("truncated data returns error", func(t *testing.T) {
		r := util.NewReader([]byte{0x05}) // claims 5 bytes but none follow
		_, err := r.ReadIntBytes()
		require.Error(t, err)
	})
}

func TestReaderReadVarIntOptional(t *testing.T) {
	t.Parallel()

	t.Run("regular value", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteVarInt(42)
		r := util.NewReader(w.Buf)
		v, err := r.ReadVarIntOptional()
		require.NoError(t, err)
		require.NotNil(t, v)
		require.Equal(t, uint64(42), *v)
	})

	t.Run("MaxUint64 returns nil", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteNegativeOne()
		r := util.NewReader(w.Buf)
		v, err := r.ReadVarIntOptional()
		require.NoError(t, err)
		require.Nil(t, v)
	})
}

func TestReaderReadVarInt32(t *testing.T) {
	t.Parallel()

	w := util.NewWriter()
	w.WriteVarInt(255)
	r := util.NewReader(w.Buf)
	v, err := r.ReadVarInt32()
	require.NoError(t, err)
	require.Equal(t, uint32(255), v)
}

func TestReaderReadIoReader(t *testing.T) {
	t.Parallel()

	t.Run("reads into buffer", func(t *testing.T) {
		r := util.NewReader([]byte{0x01, 0x02, 0x03})
		buf := make([]byte, 2)
		n, err := r.Read(buf)
		require.NoError(t, err)
		require.Equal(t, 2, n)
		require.Equal(t, []byte{0x01, 0x02}, buf)
	})

	t.Run("past end returns error", func(t *testing.T) {
		r := util.NewReader([]byte{})
		buf := make([]byte, 1)
		_, err := r.Read(buf)
		require.Error(t, err)
	})
}

func TestReaderReadRemainingEmpty(t *testing.T) {
	t.Parallel()

	r := util.NewReader([]byte{0x01})
	_, _ = r.ReadByte()
	result := r.ReadRemaining()
	require.Nil(t, result)
}

func TestReaderReadString(t *testing.T) {
	t.Parallel()

	t.Run(subTestNonEmptyString, func(t *testing.T) {
		w := util.NewWriter()
		w.WriteString("hello")
		r := util.NewReader(w.Buf)
		s, err := r.ReadString()
		require.NoError(t, err)
		require.Equal(t, "hello", s)
	})

	t.Run("zero-length string returns empty", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteVarInt(0)
		r := util.NewReader(w.Buf)
		s, err := r.ReadString()
		require.NoError(t, err)
		require.Equal(t, "", s)
	})

	t.Run("MaxUint64 length returns empty", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteNegativeOne()
		r := util.NewReader(w.Buf)
		s, err := r.ReadString()
		require.NoError(t, err)
		require.Equal(t, "", s)
	})

	t.Run("truncated bytes returns error", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteVarInt(10)
		r := util.NewReader(w.Buf)
		_, err := r.ReadString()
		require.Error(t, err)
	})
}

func TestReaderReadOptionalString(t *testing.T) {
	t.Parallel()

	t.Run("nil writes negative-one, reads empty", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteOptionalString("")
		r := util.NewReader(w.Buf)
		s, err := r.ReadOptionalString()
		require.NoError(t, err)
		require.Equal(t, "", s)
	})

	t.Run("non-empty string round-trip", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteOptionalString("test")
		r := util.NewReader(w.Buf)
		s, err := r.ReadOptionalString()
		require.NoError(t, err)
		require.Equal(t, "test", s)
	})
}

func TestReaderReadOptionalBytes(t *testing.T) {
	t.Parallel()

	t.Run("no options - empty returns nil", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteOptionalBytes(nil)
		r := util.NewReader(w.Buf)
		b, err := r.ReadOptionalBytes()
		require.NoError(t, err)
		require.Nil(t, b)
	})

	t.Run("no options - non-empty round-trip", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteOptionalBytes([]byte{0x01, 0x02})
		r := util.NewReader(w.Buf)
		b, err := r.ReadOptionalBytes()
		require.NoError(t, err)
		require.Equal(t, []byte{0x01, 0x02}, b)
	})

	t.Run("with flag - no data returns nil", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteOptionalBytes(nil, util.BytesOptionWithFlag)
		r := util.NewReader(w.Buf)
		b, err := r.ReadOptionalBytes(util.BytesOptionWithFlag)
		require.NoError(t, err)
		require.Nil(t, b)
	})

	t.Run("with flag - data round-trip", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteOptionalBytes([]byte{0xAB}, util.BytesOptionWithFlag)
		r := util.NewReader(w.Buf)
		b, err := r.ReadOptionalBytes(util.BytesOptionWithFlag)
		require.NoError(t, err)
		require.Equal(t, []byte{0xAB}, b)
	})

	t.Run("with TxIdLen - reads 32 bytes", func(t *testing.T) {
		data := make([]byte, 32)
		for i := range data {
			data[i] = byte(i)
		}
		w := util.NewWriter()
		w.WriteOptionalBytes(data, util.BytesOptionTxIdLen)
		r := util.NewReader(w.Buf)
		b, err := r.ReadOptionalBytes(util.BytesOptionTxIdLen)
		require.NoError(t, err)
		require.Equal(t, data, b)
	})

	t.Run("with flag - truncated returns error", func(t *testing.T) {
		r := util.NewReader([]byte{})
		_, err := r.ReadOptionalBytes(util.BytesOptionWithFlag)
		require.Error(t, err)
	})
}

func TestReaderReadOptionalUint32(t *testing.T) {
	t.Parallel()

	t.Run("regular value", func(t *testing.T) {
		w := util.NewWriter()
		v := uint32(12345)
		w.WriteOptionalUint32(&v)
		r := util.NewReader(w.Buf)
		result, err := r.ReadOptionalUint32()
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, v, *result)
	})

	t.Run("MaxUint64 returns nil", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteOptionalUint32(nil)
		r := util.NewReader(w.Buf)
		result, err := r.ReadOptionalUint32()
		require.NoError(t, err)
		require.Nil(t, result)
	})
}

func TestReaderReadOptionalBool(t *testing.T) {
	t.Parallel()

	t.Run("true", func(t *testing.T) {
		w := util.NewWriter()
		b := true
		w.WriteOptionalBool(&b)
		r := util.NewReader(w.Buf)
		result, err := r.ReadOptionalBool()
		require.NoError(t, err)
		require.NotNil(t, result)
		require.True(t, *result)
	})

	t.Run("false", func(t *testing.T) {
		w := util.NewWriter()
		b := false
		w.WriteOptionalBool(&b)
		r := util.NewReader(w.Buf)
		result, err := r.ReadOptionalBool()
		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, *result)
	})

	t.Run("0xFF returns nil", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteOptionalBool(nil)
		r := util.NewReader(w.Buf)
		result, err := r.ReadOptionalBool()
		require.NoError(t, err)
		require.Nil(t, result)
	})

	t.Run("empty returns error", func(t *testing.T) {
		r := util.NewReader([]byte{})
		_, err := r.ReadOptionalBool()
		require.Error(t, err)
	})
}

func TestReaderReadTxidSlice(t *testing.T) {
	t.Parallel()

	t.Run("two txids round-trip", func(t *testing.T) {
		txid1, _ := chainhash.NewHashFromHex("0000000000000000000000000000000000000000000000000000000000000001")
		txid2, _ := chainhash.NewHashFromHex("0000000000000000000000000000000000000000000000000000000000000002")

		w := util.NewWriter()
		err := w.WriteTxidSlice([]chainhash.Hash{*txid1, *txid2})
		require.NoError(t, err)

		r := util.NewReader(w.Buf)
		result, err := r.ReadTxidSlice()
		require.NoError(t, err)
		require.Len(t, result, 2)
		require.Equal(t, *txid1, result[0])
		require.Equal(t, *txid2, result[1])
	})

	t.Run("nil slice (MaxUint64) returns nil", func(t *testing.T) {
		w := util.NewWriter()
		err := w.WriteTxidSlice(nil)
		require.NoError(t, err)

		r := util.NewReader(w.Buf)
		result, err := r.ReadTxidSlice()
		require.NoError(t, err)
		require.Nil(t, result)
	})

	t.Run("truncated txid bytes returns error", func(t *testing.T) {
		// varint says 1 txid but only 10 bytes follow
		w := util.NewWriter()
		w.WriteVarInt(1)
		w.WriteBytes(make([]byte, 10))
		r := util.NewReader(w.Buf)
		_, err := r.ReadTxidSlice()
		require.Error(t, err)
	})
}

func TestReaderReadStringSlice(t *testing.T) {
	t.Parallel()

	t.Run("non-nil slice round-trip", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteStringSlice([]string{"foo", "bar"})
		r := util.NewReader(w.Buf)
		result, err := r.ReadStringSlice()
		require.NoError(t, err)
		require.Equal(t, []string{"foo", "bar"}, result)
	})

	t.Run("nil (MaxUint64) returns nil", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteStringSlice(nil)
		r := util.NewReader(w.Buf)
		result, err := r.ReadStringSlice()
		require.NoError(t, err)
		require.Nil(t, result)
	})
}

func TestReaderReadOptionalToHex(t *testing.T) {
	t.Parallel()

	t.Run("non-empty data returns hex", func(t *testing.T) {
		w := util.NewWriter()
		_ = w.WriteOptionalFromHex("deadbeef")
		r := util.NewReader(w.Buf)
		s, err := r.ReadOptionalToHex()
		require.NoError(t, err)
		require.Equal(t, "deadbeef", s)
	})

	t.Run("MaxUint64 returns empty string", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteNegativeOne()
		r := util.NewReader(w.Buf)
		s, err := r.ReadOptionalToHex()
		require.NoError(t, err)
		require.Equal(t, "", s)
	})
}

func TestReaderReadBytesNegativeLength(t *testing.T) {
	t.Parallel()

	r := util.NewReader([]byte{0x01, 0x02, 0x03})
	_, err := r.ReadBytes(-1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid read length")
}

// ---------------------------------------------------------------------------
// ReaderHoldError
// ---------------------------------------------------------------------------

func TestReaderHoldErrorBasic(t *testing.T) {
	t.Parallel()

	t.Run("IsComplete false then true", func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{0x01})
		require.False(t, r.IsComplete())
		r.ReadByte()
		require.True(t, r.IsComplete())
	})

	t.Run("CheckComplete no error on fully consumed", func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{0x01})
		r.ReadByte()
		r.CheckComplete()
		require.NoError(t, r.Err)
	})

	t.Run("CheckComplete error when not fully consumed", func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{0x01, 0x02})
		r.ReadByte()
		r.CheckComplete()
		require.Error(t, r.Err)
	})

	t.Run("CheckComplete skips if already has error", func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{})
		r.ReadByte() // sets err
		originalErr := r.Err
		r.CheckComplete()
		require.Equal(t, originalErr, r.Err) // err unchanged
	})
}

func TestReaderHoldErrorReadVarInt(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteVarInt(99)
		r := util.NewReaderHoldError(w.Buf)
		v := r.ReadVarInt()
		require.NoError(t, r.Err)
		require.Equal(t, uint64(99), v)
	})

	t.Run("propagates prior error", func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{})
		r.ReadByte() // force error
		v := r.ReadVarInt()
		require.Equal(t, uint64(0), v)
	})
}

func TestReaderHoldErrorReadVarInt32(t *testing.T) {
	t.Parallel()

	w := util.NewWriter()
	w.WriteVarInt(42)
	r := util.NewReaderHoldError(w.Buf)
	v := r.ReadVarInt32()
	require.NoError(t, r.Err)
	require.Equal(t, uint32(42), v)
}

func TestReaderHoldErrorReadOptionalUint32(t *testing.T) {
	t.Parallel()

	t.Run("value", func(t *testing.T) {
		w := util.NewWriter()
		v := uint32(7)
		w.WriteOptionalUint32(&v)
		r := util.NewReaderHoldError(w.Buf)
		result := r.ReadOptionalUint32()
		require.NoError(t, r.Err)
		require.NotNil(t, result)
		require.Equal(t, uint32(7), *result)
	})

	t.Run(subTestNilOnPriorError, func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{})
		r.ReadByte()
		result := r.ReadOptionalUint32()
		require.Nil(t, result)
	})
}

func TestReaderHoldErrorReadBytes(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{0x01, 0x02, 0x03})
		b := r.ReadBytes(2)
		require.NoError(t, r.Err)
		require.Equal(t, []byte{0x01, 0x02}, b)
	})

	t.Run("with error message", func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{0x01})
		b := r.ReadBytes(5, "custom error")
		require.Error(t, r.Err)
		require.Contains(t, r.Err.Error(), "custom error")
		require.Nil(t, b)
	})

	t.Run(subTestNilOnPriorError, func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{})
		r.ReadByte()
		b := r.ReadBytes(2)
		require.Nil(t, b)
	})
}

func TestReaderHoldErrorReadBytesReverse(t *testing.T) {
	t.Parallel()

	t.Run("success even-length", func(t *testing.T) {
		// Even length: reverse works correctly
		r := util.NewReaderHoldError([]byte{0x01, 0x02, 0x03, 0x04})
		b := r.ReadBytesReverse(4)
		require.NoError(t, r.Err)
		require.Equal(t, []byte{0x04, 0x03, 0x02, 0x01}, b)
	})

	t.Run(subTestNilOnPriorError, func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{})
		r.ReadByte()
		b := r.ReadBytesReverse(3)
		require.Nil(t, b)
	})
}

func TestReaderHoldErrorReadBase64Int(t *testing.T) {
	t.Parallel()

	data := []byte{0x01, 0x02}
	w := util.NewWriter()
	w.WriteIntBytes(data)
	r := util.NewReaderHoldError(w.Buf)
	s := r.ReadBase64Int()
	require.NoError(t, r.Err)
	require.Equal(t, base64.StdEncoding.EncodeToString(data), s)
}

func TestReaderHoldErrorReadBase64(t *testing.T) {
	t.Parallel()

	r := util.NewReaderHoldError([]byte{0xAB, 0xCD})
	s := r.ReadBase64(2)
	require.NoError(t, r.Err)
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte{0xAB, 0xCD}), s)
}

func TestReaderHoldErrorReadHex(t *testing.T) {
	t.Parallel()

	r := util.NewReaderHoldError([]byte{0xAB, 0xCD})
	s := r.ReadHex(2)
	require.NoError(t, r.Err)
	require.Equal(t, "abcd", s)
}

func TestReaderHoldErrorReadRemainingHex(t *testing.T) {
	t.Parallel()

	r := util.NewReaderHoldError([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	s := r.ReadRemainingHex()
	require.Equal(t, "deadbeef", s)
}

func TestReaderHoldErrorReadIntBytes(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteIntBytes([]byte{0x01, 0x02})
		r := util.NewReaderHoldError(w.Buf)
		b := r.ReadIntBytes()
		require.NoError(t, r.Err)
		require.Equal(t, []byte{0x01, 0x02}, b)
	})

	t.Run(subTestNilOnPriorError, func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{})
		r.ReadByte()
		b := r.ReadIntBytes()
		require.Nil(t, b)
	})
}

func TestReaderHoldErrorReadIntBytesHex(t *testing.T) {
	t.Parallel()

	w := util.NewWriter()
	w.WriteIntBytes([]byte{0xAB, 0xCD})
	r := util.NewReaderHoldError(w.Buf)
	s := r.ReadIntBytesHex()
	require.NoError(t, r.Err)
	require.Equal(t, "abcd", s)
}

func TestReaderHoldErrorReadByte(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{0x42})
		b := r.ReadByte()
		require.NoError(t, r.Err)
		require.Equal(t, byte(0x42), b)
	})

	t.Run("error past end", func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{})
		b := r.ReadByte()
		require.Error(t, r.Err)
		require.Equal(t, byte(0), b)
	})

	t.Run("zero on prior error", func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{})
		r.ReadByte()
		b := r.ReadByte()
		require.Equal(t, byte(0), b)
	})
}

func TestReaderHoldErrorReadOptionalBool(t *testing.T) {
	t.Parallel()

	t.Run("true", func(t *testing.T) {
		w := util.NewWriter()
		b := true
		w.WriteOptionalBool(&b)
		r := util.NewReaderHoldError(w.Buf)
		result := r.ReadOptionalBool()
		require.NoError(t, r.Err)
		require.NotNil(t, result)
		require.True(t, *result)
	})

	t.Run(subTestNilOnPriorError, func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{})
		r.ReadByte()
		result := r.ReadOptionalBool()
		require.Nil(t, result)
	})
}

func TestReaderHoldErrorReadTxidSlice(t *testing.T) {
	t.Parallel()

	txid1, _ := chainhash.NewHashFromHex("0000000000000000000000000000000000000000000000000000000000000001")
	w := util.NewWriter()
	err := w.WriteTxidSlice([]chainhash.Hash{*txid1})
	require.NoError(t, err)

	r := util.NewReaderHoldError(w.Buf)
	result := r.ReadTxidSlice()
	require.NoError(t, r.Err)
	require.Len(t, result, 1)
}

func TestReaderHoldErrorReadOptionalBytes(t *testing.T) {
	t.Parallel()

	t.Run("non-empty round-trip", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteOptionalBytes([]byte{0x01})
		r := util.NewReaderHoldError(w.Buf)
		b := r.ReadOptionalBytes()
		require.NoError(t, r.Err)
		require.Equal(t, []byte{0x01}, b)
	})

	t.Run(subTestNilOnPriorError, func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{})
		r.ReadByte()
		b := r.ReadOptionalBytes()
		require.Nil(t, b)
	})
}

func TestReaderHoldErrorReadString(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteString("world")
		r := util.NewReaderHoldError(w.Buf)
		s := r.ReadString()
		require.NoError(t, r.Err)
		require.Equal(t, "world", s)
	})

	t.Run("with custom error message", func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{})
		s := r.ReadString("my error")
		require.Error(t, r.Err)
		require.Contains(t, r.Err.Error(), "my error")
		require.Equal(t, "", s)
	})

	t.Run(subTestEmptyOnPriorError, func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{})
		r.ReadByte()
		s := r.ReadString()
		require.Equal(t, "", s)
	})
}

func TestReaderHoldErrorReadOptionalString(t *testing.T) {
	t.Parallel()

	t.Run(subTestNonEmptyString, func(t *testing.T) {
		w := util.NewWriter()
		w.WriteOptionalString("test")
		r := util.NewReaderHoldError(w.Buf)
		s := r.ReadOptionalString()
		require.NoError(t, r.Err)
		require.Equal(t, "test", s)
	})

	t.Run(subTestEmptyOnPriorError, func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{})
		r.ReadByte()
		s := r.ReadOptionalString()
		require.Equal(t, "", s)
	})
}

func TestReaderHoldErrorReadStringSlice(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		w := util.NewWriter()
		w.WriteStringSlice([]string{"a", "b"})
		r := util.NewReaderHoldError(w.Buf)
		result := r.ReadStringSlice()
		require.NoError(t, r.Err)
		require.Equal(t, []string{"a", "b"}, result)
	})

	t.Run(subTestNilOnPriorError, func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{})
		r.ReadByte()
		result := r.ReadStringSlice()
		require.Nil(t, result)
	})
}

func TestReaderHoldErrorReadOptionalToHex(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		w := util.NewWriter()
		err := w.WriteOptionalFromHex("abcd")
		require.NoError(t, err)
		r := util.NewReaderHoldError(w.Buf)
		s := r.ReadOptionalToHex()
		require.NoError(t, r.Err)
		require.Equal(t, "abcd", s)
	})

	t.Run(subTestEmptyOnPriorError, func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{})
		r.ReadByte()
		s := r.ReadOptionalToHex()
		require.Equal(t, "", s)
	})
}

func TestReaderHoldErrorReadRemaining(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{0x01, 0x02, 0x03})
		result := r.ReadRemaining()
		require.Equal(t, []byte{0x01, 0x02, 0x03}, result)
	})

	t.Run(subTestNilOnPriorError, func(t *testing.T) {
		r := util.NewReaderHoldError([]byte{})
		r.ReadByte()
		result := r.ReadRemaining()
		require.Nil(t, result)
	})
}

// ---------------------------------------------------------------------------
// Utility helper functions
// ---------------------------------------------------------------------------

func TestPtrToBool(t *testing.T) {
	t.Parallel()

	trueVal := true
	falseVal := false

	require.True(t, util.PtrToBool(&trueVal))
	require.False(t, util.PtrToBool(&falseVal))
	require.False(t, util.PtrToBool(nil))
}

func TestBoolPtr(t *testing.T) {
	t.Parallel()

	p := util.BoolPtr(true)
	require.NotNil(t, p)
	require.True(t, *p)

	p2 := util.BoolPtr(false)
	require.NotNil(t, p2)
	require.False(t, *p2)
}

func TestUint32Ptr(t *testing.T) {
	t.Parallel()

	p := util.Uint32Ptr(42)
	require.NotNil(t, p)
	require.Equal(t, uint32(42), *p)
}

// ---------------------------------------------------------------------------
// WriteStringSlice + ReadStringSlice empty slice
// ---------------------------------------------------------------------------

func TestWriterReadStringSliceEmptySlice(t *testing.T) {
	t.Parallel()

	w := util.NewWriter()
	w.WriteStringSlice([]string{})
	r := util.NewReader(w.Buf)
	result, err := r.ReadStringSlice()
	require.NoError(t, err)
	require.Equal(t, []string{}, result)
}

// ---------------------------------------------------------------------------
// VarInt ReadFrom edge cases
// ---------------------------------------------------------------------------

func TestVarIntReadFromAllPrefixes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value uint64
	}{
		{"1 byte", 200},
		{"3 byte", 300},
		{"5 byte", 70000},
		{"9 byte", 5000000000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := util.NewWriter()
			w.WriteVarInt(tt.value)
			r := util.NewReader(w.Buf)
			got, err := r.ReadVarInt()
			require.NoError(t, err)
			require.Equal(t, tt.value, got)
		})
	}
}

// ---------------------------------------------------------------------------
// hex encoding helpers
// ---------------------------------------------------------------------------

func TestReadOptionalToHexZeroLength(t *testing.T) {
	t.Parallel()

	w := util.NewWriter()
	w.WriteVarInt(0)
	r := util.NewReader(w.Buf)
	s, err := r.ReadOptionalToHex()
	require.NoError(t, err)
	require.Equal(t, "", s)
}

func TestReadOptionalToHexContent(t *testing.T) {
	t.Parallel()

	data, _ := hex.DecodeString("cafebabe")
	w := util.NewWriter()
	w.WriteIntBytes(data)
	r := util.NewReader(w.Buf)
	s, err := r.ReadOptionalToHex()
	require.NoError(t, err)
	require.Equal(t, "cafebabe", s)
}
