package util_test

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/util"
)

// TestReaderReadVarIntOptionalError covers the varint-read failure branch of
// ReadVarIntOptional (reader.go:87-88).
func TestReaderReadVarIntOptionalError(t *testing.T) {
	t.Parallel()

	r := util.NewReader([]byte{})
	v, err := r.ReadVarIntOptional()
	require.Error(t, err)
	require.Nil(t, v)
}

// TestReaderReadOptionalStringError covers the propagated-error branch of
// ReadOptionalString (reader.go:137-138).
func TestReaderReadOptionalStringError(t *testing.T) {
	t.Parallel()

	r := util.NewReader([]byte{})
	s, err := r.ReadOptionalString()
	require.Error(t, err)
	require.Empty(t, s)
}

// TestReaderReadOptionalBytesLengthError covers the length-varint failure branch
// of ReadOptionalBytes when neither the flag nor txid-length options are set
// (reader.go:173-174).
func TestReaderReadOptionalBytesLengthError(t *testing.T) {
	t.Parallel()

	r := util.NewReader([]byte{})
	b, err := r.ReadOptionalBytes()
	require.Error(t, err)
	require.Contains(t, err.Error(), "error reading length")
	require.Nil(t, b)
}

// TestReaderReadOptionalUint32Errors covers both error branches of
// ReadOptionalUint32: the varint-read failure (reader.go:185-186) and the
// value-exceeds-uint32 guard (reader.go:192-193).
func TestReaderReadOptionalUint32Errors(t *testing.T) {
	t.Parallel()

	t.Run("varint read fails", func(t *testing.T) {
		t.Parallel()

		r := util.NewReader([]byte{})
		v, err := r.ReadOptionalUint32()
		require.Error(t, err)
		require.Nil(t, v)
	})

	t.Run("value exceeds uint32 maximum", func(t *testing.T) {
		t.Parallel()

		// A value above MaxUint32 (but not the MaxUint64 sentinel) must error.
		w := util.NewWriter()
		w.WriteVarInt(uint64(math.MaxUint32) + 1)
		r := util.NewReader(w.Buf)
		v, err := r.ReadOptionalUint32()
		require.Error(t, err)
		require.Contains(t, err.Error(), "exceeds uint32 maximum")
		require.Nil(t, v)
	})
}

// TestReaderReadTxidSliceCountError covers the count-varint failure branch of
// ReadTxidSlice (reader.go:213-214).
func TestReaderReadTxidSliceCountError(t *testing.T) {
	t.Parallel()

	r := util.NewReader([]byte{})
	result, err := r.ReadTxidSlice()
	require.Error(t, err)
	require.Contains(t, err.Error(), "slice txid count")
	require.Nil(t, result)
}

// TestReaderReadStringSliceErrors covers the count-varint failure
// (reader.go:238-239), the count-exceeds-int guard (reader.go:244-245), and the
// per-element string read failure (reader.go:251-252).
func TestReaderReadStringSliceErrors(t *testing.T) {
	t.Parallel()

	t.Run("count varint fails", func(t *testing.T) {
		t.Parallel()

		r := util.NewReader([]byte{})
		result, err := r.ReadStringSlice()
		require.Error(t, err)
		require.Contains(t, err.Error(), "slice string count")
		require.Nil(t, result)
	})

	t.Run("count exceeds max int", func(t *testing.T) {
		t.Parallel()

		// MaxInt64 is >= math.MaxInt on 64-bit platforms but is not the
		// MaxUint64 "nil" sentinel, so it trips the size guard.
		w := util.NewWriter()
		w.WriteVarInt(uint64(math.MaxInt64))
		r := util.NewReader(w.Buf)
		result, err := r.ReadStringSlice()
		require.Error(t, err)
		require.Contains(t, err.Error(), "exceeds maximum int size")
		require.Nil(t, result)
	})

	t.Run("element string read fails", func(t *testing.T) {
		t.Parallel()

		// count=1 followed by a string whose length prefix promises more bytes
		// than are present.
		w := util.NewWriter()
		w.WriteVarInt(1)  // count
		w.WriteVarInt(10) // string length with no following bytes
		r := util.NewReader(w.Buf)
		result, err := r.ReadStringSlice()
		require.Error(t, err)
		require.Contains(t, err.Error(), "error reading string for slice")
		require.Nil(t, result)
	})
}

// TestReaderReadOptionalToHexErrors covers the length-varint failure
// (reader.go:261-262) and the data-read failure (reader.go:268-269) branches of
// ReadOptionalToHex.
func TestReaderReadOptionalToHexErrors(t *testing.T) {
	t.Parallel()

	t.Run("length varint fails", func(t *testing.T) {
		t.Parallel()

		r := util.NewReader([]byte{})
		s, err := r.ReadOptionalToHex()
		require.Error(t, err)
		require.Contains(t, err.Error(), "data length for optional hex")
		require.Empty(t, s)
	})

	t.Run("data bytes read fails", func(t *testing.T) {
		t.Parallel()

		w := util.NewWriter()
		w.WriteVarInt(10) // claims 10 bytes but none follow
		r := util.NewReader(w.Buf)
		s, err := r.ReadOptionalToHex()
		require.Error(t, err)
		require.Contains(t, err.Error(), "data bytes for optional hex")
		require.Empty(t, s)
	})
}

// TestReaderHoldErrorReadVarInt32PriorError covers the early-return-on-prior-error
// branch of ReaderHoldError.ReadVarInt32 (reader.go:308-309).
func TestReaderHoldErrorReadVarInt32PriorError(t *testing.T) {
	t.Parallel()

	r := util.NewReaderHoldError([]byte{})
	r.ReadByteValue() // sets r.Err
	v := r.ReadVarInt32()
	require.Error(t, r.Err)
	require.Equal(t, uint32(0), v)
}

// TestReaderHoldErrorReadTxidSlicePriorError covers the early-return-on-prior-error
// branch of ReaderHoldError.ReadTxidSlice (reader.go:406-407).
func TestReaderHoldErrorReadTxidSlicePriorError(t *testing.T) {
	t.Parallel()

	r := util.NewReaderHoldError([]byte{})
	r.ReadByteValue() // sets r.Err
	result := r.ReadTxidSlice()
	require.Error(t, r.Err)
	require.Nil(t, result)
}

// TestReaderHoldErrorReadBytesErrorNoMessage covers the getErr branch where an
// error is returned without a custom message wrapper (reader.go:470-471).
func TestReaderHoldErrorReadBytesErrorNoMessage(t *testing.T) {
	t.Parallel()

	// A fresh reader (no prior error) that reads past the end, with no custom
	// error message, exercises getErr's len(errMsg)==0 return path.
	r := util.NewReaderHoldError([]byte{0x01})
	b := r.ReadBytes(5)
	require.Error(t, r.Err)
	require.Contains(t, r.Err.Error(), "read past end of data")
	require.Nil(t, b)
}
