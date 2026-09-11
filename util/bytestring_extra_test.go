package util_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/util"
)

// TestByteStringUnmarshalJSONError covers the json.Unmarshal failure branch of
// ByteString.UnmarshalJSON (bytestring.go:30-31), where the input is not a JSON
// string.
func TestByteStringUnmarshalJSONError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{"number is not a string", "123"},
		{"malformed json", "{"},
		{"object is not a string", `{"a":1}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var bs util.ByteString
			err := bs.UnmarshalJSON([]byte(tt.input))
			require.Error(t, err)
		})
	}
}
