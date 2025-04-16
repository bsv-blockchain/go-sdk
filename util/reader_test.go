package util_test

import (
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestWriterReader(t *testing.T) {
	tests := []struct {
		name     string
		writeFn  func(*util.Writer)
		readFn   func(*util.Reader) (interface{}, error)
		expected interface{}
	}{
		{
			name: "writeByte/readByte",
			writeFn: func(w *util.Writer) {
				w.WriteByte(0xAB)
			},
			readFn: func(r *util.Reader) (interface{}, error) {
				return r.ReadByte()
			},
			expected: byte(0xAB),
		},
		{
			name: "writeBytes/readBytes",
			writeFn: func(w *util.Writer) {
				w.WriteBytes([]byte{0x01, 0x02, 0x03})
			},
			readFn: func(r *util.Reader) (interface{}, error) {
				return r.ReadBytes(3)
			},
			expected: []byte{0x01, 0x02, 0x03},
		},
		{
			name: "writeVarInt/readVarInt",
			writeFn: func(w *util.Writer) {
				w.WriteVarInt(123456)
			},
			readFn: func(r *util.Reader) (interface{}, error) {
				return r.ReadVarInt()
			},
			expected: uint64(123456),
		},
		{
			name: "writeVarInt/readVarInt zero",
			writeFn: func(w *util.Writer) {
				w.WriteVarInt(0)
			},
			readFn: func(r *util.Reader) (interface{}, error) {
				return r.ReadVarInt()
			},
			expected: uint64(0),
		},
		{
			name: "readRemaining",
			writeFn: func(w *util.Writer) {
				w.WriteBytes([]byte{0x01, 0x02, 0x03})
			},
			readFn: func(r *util.Reader) (interface{}, error) {
				return r.ReadRemaining(), nil
			},
			expected: []byte{0x01, 0x02, 0x03},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := util.NewWriter()
			tt.writeFn(w)

			r := util.NewReader(w.Buf)
			got, err := tt.readFn(r)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			require.Equal(t, tt.expected, got)
		})
	}
}

func TestReaderErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		readFn  func(*util.Reader) (interface{}, error)
		wantErr string
	}{
		{
			name: "readByte past end",
			data: []byte{},
			readFn: func(r *util.Reader) (interface{}, error) {
				return r.ReadByte()
			},
			wantErr: "read past end of data",
		},
		{
			name: "readBytes past end",
			data: []byte{0x01},
			readFn: func(r *util.Reader) (interface{}, error) {
				return r.ReadBytes(2)
			},
			wantErr: "read past end of data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := util.NewReader(tt.data)
			_, err := tt.readFn(r)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != tt.wantErr {
				t.Errorf("got error %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}
