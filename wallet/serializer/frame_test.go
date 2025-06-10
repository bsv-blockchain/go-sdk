package serializer

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/v2/wallet"
	"github.com/stretchr/testify/assert"
)

func TestRequestFrameRoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		call       byte
		originator string
		params     []byte
	}{
		{
			name:       "empty params",
			call:       0x01,
			originator: "test-originator",
		},
		{
			name:       "with params",
			call:       0x02,
			originator: "another-originator",
			params:     []byte{0x01, 0x02, 0x03},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create and serialize request frame
			frame := RequestFrame{
				Call:       tt.call,
				Originator: tt.originator,
				Params:     tt.params,
			}
			serialized := WriteRequestFrame(frame)

			// Deserialize and verify
			deserialized, err := ReadRequestFrame(serialized)
			assert.NoError(t, err, "deserializing request frame should not error")
			assert.Equal(t, tt.call, deserialized.Call, "deserialized call byte should match original")
			assert.Equal(t, tt.originator, deserialized.Originator, "deserialized originator should match original")
			assert.Equal(t, tt.params, deserialized.Params, "deserialized params should match original")
		})
	}
}

func TestResultFrameRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		result []byte
		err    *wallet.Error
	}{
		{
			name:   "success with data",
			result: []byte{0x01, 0x02, 0x03},
		},
		{
			name: "success empty",
		},
		{
			name: "error case",
			err: &wallet.Error{
				Code:    0x01,
				Message: "test error",
				Stack:   "stack trace",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Serialize result
			serialized := WriteResultFrame(tt.result, tt.err)

			// Deserialize and verify
			result, err := ReadResultFrame(serialized)
			if tt.err != nil {
				assert.Error(t, err, "deserializing an error frame should produce an error")
				walletErr, ok := err.(*wallet.Error)
				assert.True(t, ok, "error should be of type *wallet.Error")
				assert.Equal(t, tt.err.Code, walletErr.Code, "deserialized error code should match original")
				assert.Equal(t, tt.err.Message, walletErr.Message, "deserialized error message should match original")
				assert.Equal(t, tt.err.Stack, walletErr.Stack, "deserialized error stack should match original")
			} else {
				assert.NoError(t, err, "deserializing a success frame should not error")
				assert.Equal(t, tt.result, result, "deserialized success result should match original")
			}
		})
	}
}
