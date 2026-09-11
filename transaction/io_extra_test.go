package transaction

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
)

func TestOutputReadFromRoundTrip(t *testing.T) {
	t.Parallel()
	ls := script.NewFromBytes([]byte{0x51, 0x52, 0x53})
	out := &TransactionOutput{Satoshis: 4242, LockingScript: ls}

	var got TransactionOutput
	n, err := got.ReadFrom(bytes.NewReader(out.Bytes()))
	require.NoError(t, err)
	assert.Equal(t, int64(len(out.Bytes())), n)
	assert.Equal(t, uint64(4242), got.Satoshis)
	assert.Equal(t, []byte(*ls), []byte(*got.LockingScript))
}

func TestOutputReadFromTruncated(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data []byte
	}{
		{name: "satoshis-short", data: []byte{0x01, 0x02, 0x03}},
		{name: "script-len-eof", data: make([]byte, 8)},
		{name: "script-bytes-short", data: append(make([]byte, 8), 0x05)}, // says 5 script bytes, none present
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out TransactionOutput
			_, err := out.ReadFrom(bytes.NewReader(tc.data))
			require.Error(t, err)
		})
	}
}

func TestOutputWriteToError(t *testing.T) {
	t.Parallel()
	out := &TransactionOutput{Satoshis: 1, LockingScript: script.NewFromBytes([]byte{0x51})}
	var total int64
	err := out.writeTo(&limitWriter{limit: 0}, make([]byte, 9), &total)
	require.ErrorIs(t, err, errLimitWrite)
}

func TestInputReadFromTruncated(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data []byte
	}{
		{name: "index-eof", data: make([]byte, 32)},                  // txid only
		{name: "scriptlen-eof", data: make([]byte, 36)},              // txid + index
		{name: "sequence-eof", data: append(make([]byte, 36), 0x00)}, // + empty script varint
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var in TransactionInput
			_, err := in.ReadFrom(bytes.NewReader(tc.data))
			require.Error(t, err)
		})
	}
}

func TestInputReadFromExtendedTruncated(t *testing.T) {
	t.Parallel()
	base := func() []byte {
		b := make([]byte, 0, 41)
		b = append(b, make([]byte, 32)...)    // txid
		b = append(b, 0x00, 0x00, 0x00, 0x00) // index
		b = append(b, 0x00)                   // empty script
		b = append(b, 0x00, 0x00, 0x00, 0x00) // sequence
		return b
	}
	tests := []struct {
		name string
		data []byte
	}{
		{name: "prev-satoshis-eof", data: base()},
		{name: "src-scriptlen-eof", data: append(base(), make([]byte, 8)...)},
		{name: "src-script-short", data: append(append(base(), make([]byte, 8)...), 0xFE, 0xFF, 0xFF, 0xFF, 0xFF)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var in TransactionInput
			_, err := in.ReadFromExtended(bytes.NewReader(tc.data))
			require.Error(t, err)
		})
	}
}

func TestInputWriteToErrors(t *testing.T) {
	t.Parallel()

	// Each subtest must own its scratch buffer: writeTo writes into the caller-supplied
	// scratch slice, so sharing one across parallel subtests is a data race.
	t.Run("index-write", func(t *testing.T) {
		t.Parallel()
		in := &TransactionInput{SourceTXID: &chainhash.Hash{}, SequenceNumber: 1}
		var total int64
		err := in.writeTo(&limitWriter{limit: 32}, make([]byte, 9), &total)
		require.ErrorIs(t, err, errLimitWrite)
	})

	t.Run("empty-script-write", func(t *testing.T) {
		t.Parallel()
		in := &TransactionInput{SourceTXID: &chainhash.Hash{}, SequenceNumber: 1}
		var total int64
		err := in.writeTo(&limitWriter{limit: 36}, make([]byte, 9), &total)
		require.ErrorIs(t, err, errLimitWrite)
	})

	t.Run("script-body-write", func(t *testing.T) {
		t.Parallel()
		in := &TransactionInput{
			SourceTXID:      &chainhash.Hash{},
			UnlockingScript: script.NewFromBytes([]byte{0x51, 0x52, 0x53}),
			SequenceNumber:  1,
		}
		var total int64
		err := in.writeTo(&limitWriter{limit: 37}, make([]byte, 9), &total)
		require.ErrorIs(t, err, errLimitWrite)
	})
}
