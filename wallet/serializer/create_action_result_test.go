package serializer

import (
	"math"
	"testing"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestCreateActionResultSerializeAndDeserialize(t *testing.T) {
	tests := []struct {
		name   string
		result *wallet.CreateActionResult
	}{
		{
			name: "full result",
			result: &wallet.CreateActionResult{
				Txid: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				Tx:   []byte{0x01, 0x02, 0x03},
				NoSendChange: []string{
					"abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234.0",
					"abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234.1",
				},
				SendWithResults: []wallet.SendWithResult{
					{
						Txid:   "8a552c995db3602e85bb9df911803897d1ea17ba5cdd198605d014be49db9f72",
						Status: wallet.ActionResultStatusUnproven,
					},
					{
						Txid:   "490c292a700c55d5e62379828d60bf6c61850fbb4d13382f52021d3796221981",
						Status: wallet.ActionResultStatusSending,
					},
				},
				SignableTransaction: &wallet.SignableTransaction{
					Tx:        []byte{0x04, 0x05, 0x06},
					Reference: "test-ref",
				},
			},
		},
		{
			name:   "minimal result",
			result: &wallet.CreateActionResult{},
		},
		{
			name: "with tx only",
			result: &wallet.CreateActionResult{
				Tx: []byte{0x07, 0x08, 0x09},
			},
		},
		{
			name: "with noSendChange only",
			result: &wallet.CreateActionResult{
				NoSendChange: []string{
					"abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234.0",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Serialize
			data, err := SerializeCreateActionResult(tt.result)
			require.NoError(t, err, "serializing CreateActionResult should not error")
			require.NotEmpty(t, data, "serialized data should not be empty")

			// Deserialize
			result, err := DeserializeCreateActionResult(data)
			require.NoError(t, err, "deserializing CreateActionResult should not error")

			// Compare
			require.Equal(t, tt.result, result, "deserialized result should match original result")
		})
	}
}

func TestDeserializeCreateActionResultErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		err  string
	}{
		{
			name: "empty data",
			data: []byte{},
			err:  "empty response data",
		},
		{
			name: "invalid txid length",
			data: func() []byte {
				w := util.NewWriter()
				w.WriteByte(1)                   // txid flag
				w.WriteBytes([]byte{0x01, 0x02}) // invalid length
				return w.Buf
			}(),
			err: "response indicates failure: 1",
		},
		{
			name: "invalid status code",
			data: func() []byte {
				w := util.NewWriter()
				// success byte
				w.WriteByte(0)
				// txid flag
				w.WriteByte(0)
				// tx flag
				w.WriteByte(0)
				// noSendChange (nil)
				w.WriteVarInt(math.MaxUint64)
				// sendWithResults (1 item)
				w.WriteVarInt(1)
				// txid
				w.WriteBytes(make([]byte, 32))
				// invalid status
				w.WriteByte(99)
				// signable tx flag
				w.WriteByte(0)
				return w.Buf
			}(),
			err: "invalid status code: 99",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeserializeCreateActionResult(tt.data)
			require.Error(t, err, "deserializing invalid data should produce an error")
			require.Contains(t, err.Error(), tt.err, "error message should contain expected substring")
		})
	}
}
