package util_test

import (
	"database/sql/driver"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/util"
)

const (
	emptyByteString    = "Empty ByteString"
	nonEmptyByteString = "Non-empty ByteString"
	validHex           = "Valid hex"
	invalidHex         = "Invalid hex"
	hello              = "Hello"
)

func TestNewByteStringFromHex(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected util.ByteString
	}{
		{emptyByteString, "", util.ByteString{}},
		{validHex, "48656c6c6f", util.ByteString(hello)},
		{invalidHex, "invalid", util.ByteString{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := util.NewByteStringFromHex(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestByteStringMarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    util.ByteString
		expected string
	}{
		{emptyByteString, util.ByteString{}, `""`},
		{nonEmptyByteString, util.ByteString(hello), `"48656c6c6f"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := json.Marshal(tt.input)
			require.NoError(t, err)
			require.Equal(t, tt.expected, string(result))
		})
	}
}

func TestByteStringUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected util.ByteString
		wantErr  bool
	}{
		{"Empty string", `""`, util.ByteString(nil), false},
		{validHex, `"48656c6c6f"`, util.ByteString(hello), false},
		{invalidHex, `"invalid"`, nil, true},
		{"Invalid JSON", `{`, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var bs util.ByteString
			err := json.Unmarshal([]byte(tt.input), &bs)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, bs)
			}
		})
	}
}

func TestByteStringString(t *testing.T) {
	tests := []struct {
		name     string
		input    util.ByteString
		expected string
	}{
		{emptyByteString, util.ByteString{}, ""},
		{nonEmptyByteString, util.ByteString(hello), "48656c6c6f"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.input.String()
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestByteStringValue(t *testing.T) {
	tests := []struct {
		name     string
		input    util.ByteString
		expected driver.Value
	}{
		{emptyByteString, util.ByteString{}, []byte{}},
		{nonEmptyByteString, util.ByteString(hello), []byte(hello)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.input.Value()
			require.NoError(t, err)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestByteStringScan(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected util.ByteString
		wantErr  bool
	}{
		{"Valid []byte", []byte(hello), util.ByteString(hello), false},
		{"Invalid type", "not a []byte", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var bs util.ByteString
			err := bs.Scan(tt.input)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, bs)
			}
		})
	}
}
