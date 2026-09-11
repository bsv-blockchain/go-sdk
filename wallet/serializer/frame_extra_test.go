package serializer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/util"
)

func TestReadRequestFrameTruncated(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty (missing call byte)", data: nil},
		{name: "missing originator length", data: []byte{0x01}},
		{
			name: "truncated originator",
			data: func() []byte {
				w := util.NewWriter()
				w.WriteByteValue(0x01) // call
				w.WriteByteValue(0x05) // originator length says 5
				w.WriteBytes([]byte{0x61, 0x62})
				return w.Buf
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadRequestFrame(tt.data)
			require.Error(t, err)
		})
	}
}

func TestReadResultFrameTruncated(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty (missing error byte)", data: nil},
		{name: "missing error message length", data: []byte{0x01}},
		{
			name: "truncated error message",
			data: func() []byte {
				w := util.NewWriter()
				w.WriteByteValue(0x01) // error code
				w.WriteVarInt(5)       // message length says 5
				return w.Buf
			}(),
		},
		{
			name: "missing stack trace length",
			data: func() []byte {
				w := util.NewWriter()
				w.WriteByteValue(0x01) // error code
				w.WriteVarInt(2)       // message length
				w.WriteBytes([]byte{0x61, 0x62})
				return w.Buf
			}(),
		},
		{
			name: "truncated stack trace",
			data: func() []byte {
				w := util.NewWriter()
				w.WriteByteValue(0x01) // error code
				w.WriteVarInt(2)       // message length
				w.WriteBytes([]byte{0x61, 0x62})
				w.WriteVarInt(5) // stack length says 5
				return w.Buf
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadResultFrame(tt.data)
			require.Error(t, err)
		})
	}
}
