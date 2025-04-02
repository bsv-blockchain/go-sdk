package serializer

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestWriterReader(t *testing.T) {
	tests := []struct {
		name     string
		writeFn  func(*writer)
		readFn   func(*reader) (interface{}, error)
		expected interface{}
	}{
		{
			name: "writeByte/readByte",
			writeFn: func(w *writer) {
				w.writeByte(0xAB)
			},
			readFn: func(r *reader) (interface{}, error) {
				return r.readByte()
			},
			expected: byte(0xAB),
		},
		{
			name: "writeBytes/readBytes",
			writeFn: func(w *writer) {
				w.writeBytes([]byte{0x01, 0x02, 0x03})
			},
			readFn: func(r *reader) (interface{}, error) {
				return r.readBytes(3)
			},
			expected: []byte{0x01, 0x02, 0x03},
		},
		{
			name: "writeVarInt/readVarInt",
			writeFn: func(w *writer) {
				w.writeVarInt(123456)
			},
			readFn: func(r *reader) (interface{}, error) {
				return r.readVarInt()
			},
			expected: uint64(123456),
		},
		{
			name: "writeVarInt/readVarInt zero",
			writeFn: func(w *writer) {
				w.writeVarInt(0)
			},
			readFn: func(r *reader) (interface{}, error) {
				return r.readVarInt()
			},
			expected: uint64(0),
		},
		{
			name: "readRemaining",
			writeFn: func(w *writer) {
				w.writeBytes([]byte{0x01, 0x02, 0x03})
			},
			readFn: func(r *reader) (interface{}, error) {
				return r.readRemaining(), nil
			},
			expected: []byte{0x01, 0x02, 0x03},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWriter()
			tt.writeFn(w)

			r := newReader(w.buf)
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
		readFn  func(*reader) (interface{}, error)
		wantErr string
	}{
		{
			name: "readByte past end",
			data: []byte{},
			readFn: func(r *reader) (interface{}, error) {
				return r.readByte()
			},
			wantErr: "read past end of data",
		},
		{
			name: "readBytes past end",
			data: []byte{0x01},
			readFn: func(r *reader) (interface{}, error) {
				return r.readBytes(2)
			},
			wantErr: "read past end of data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newReader(tt.data)
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

// boolPtr is a helper function to create a pointer to a boolean value
func boolPtr(b bool) *bool {
	return &b
}
