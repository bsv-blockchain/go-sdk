package serializer

import (
	"github.com/bsv-blockchain/go-sdk/v2/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGetHeightResult(t *testing.T) {
	tests := []struct {
		name   string
		height uint32
	}{
		{
			name:   "zero height",
			height: 0,
		},
		{
			name:   "small height",
			height: 123,
		},
		{
			name:   "large height",
			height: 123456789,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			result := &wallet.GetHeightResult{Height: tt.height}
			data, err := SerializeGetHeightResult(result)
			require.NoError(t, err, "serializing GetHeightResult should not error")

			// Test deserialization
			got, err := DeserializeGetHeightResult(data)
			require.NoError(t, err, "deserializing GetHeightResult should not error")
			require.Equal(t, result, got, "deserialized result should match original result")
		})
	}
}

func TestDeserializeGetHeightResultErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: "error reading height",
		},
		{
			name:    "invalid varint",
			data:    []byte{0xFF, 0x80}, // Invalid varint (incomplete varint)
			wantErr: "error reading height",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeserializeGetHeightResult(tt.data)
			require.Error(t, err, "deserializing invalid data should produce an error")
			require.Contains(t, err.Error(), tt.wantErr, "error message should contain expected substring")
		})
	}
}
