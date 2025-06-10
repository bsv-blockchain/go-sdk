package serializer

import (
	"github.com/bsv-blockchain/go-sdk/v2/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAuthenticatedResult(t *testing.T) {
	tests := []struct {
		name     string
		input    *wallet.AuthenticatedResult
		expected bool
	}{
		{
			name:     "authenticated true",
			input:    &wallet.AuthenticatedResult{Authenticated: true},
			expected: true,
		},
		{
			name:     "authenticated false",
			input:    &wallet.AuthenticatedResult{Authenticated: false},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeAuthenticatedResult(tt.input)
			require.NoError(t, err)
			require.Equal(t, 2, len(data)) // error byte + auth byte

			// Test deserialization
			result, err := DeserializeAuthenticatedResult(data)
			require.NoError(t, err)
			require.Equal(t, tt.expected, result.Authenticated)
		})
	}
}

func TestAuthenticatedResultErrors(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		wantError string
	}{
		{
			name:      "empty data",
			data:      []byte{},
			wantError: "invalid data length",
		},
		{
			name:      "error byte set",
			data:      []byte{1, 1}, // error byte=1
			wantError: "error byte indicates failure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeserializeAuthenticatedResult(tt.data)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantError)
		})
	}
}
