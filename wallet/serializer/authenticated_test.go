package serializer

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestIsAuthenticatedResult(t *testing.T) {
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
			data, err := SerializeIsAuthenticatedResult(tt.input)
			require.NoError(t, err)
			require.Equal(t, 1, len(data)) // auth byte

			// Test deserialization
			result, err := DeserializeIsAuthenticatedResult(data)
			require.NoError(t, err)
			require.Equal(t, tt.expected, result.Authenticated)
		})
	}
}

func TestIsAuthenticatedResultErrors(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeserializeIsAuthenticatedResult(tt.data)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestWaitAuthenticatedResult(t *testing.T) {
	// Test serialization
	input := &wallet.AuthenticatedResult{Authenticated: false}
	data, err := SerializeWaitAuthenticatedResult(input)
	require.NoError(t, err)
	require.Nil(t, data)

	// Test deserialization
	result, err := DeserializeWaitAuthenticatedResult(nil)
	require.NoError(t, err)
	require.True(t, result.Authenticated)
}
