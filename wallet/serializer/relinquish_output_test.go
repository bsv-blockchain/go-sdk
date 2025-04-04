package serializer

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRelinquishOutputArgs(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.RelinquishOutputArgs
	}{
		{
			name: "basic args",
			args: &wallet.RelinquishOutputArgs{
				Basket: "test-basket",
				Output: "1111111111111111111111111111111111111111111111111111111111111111.0",
			},
		},
		{
			name: "empty basket",
			args: &wallet.RelinquishOutputArgs{
				Basket: "",
				Output: "1111111111111111111111111111111111111111111111111111111111111111.1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeRelinquishOutputArgs(tt.args)
			require.NoError(t, err)

			// Test deserialization
			got, err := DeserializeRelinquishOutputArgs(data)
			require.NoError(t, err)

			// Compare results
			require.Equal(t, tt.args, got)
		})
	}
}

func TestRelinquishOutputResult(t *testing.T) {
	t.Run("successful relinquish", func(t *testing.T) {
		result := &wallet.RelinquishOutputResult{Relinquished: true}
		data, err := SerializeRelinquishOutputResult(result)
		require.NoError(t, err)

		got, err := DeserializeRelinquishOutputResult(data)
		require.NoError(t, err)
		require.Equal(t, result, got)
	})

	t.Run("failed relinquish", func(t *testing.T) {
		result := &wallet.RelinquishOutputResult{Relinquished: false}
		data, err := SerializeRelinquishOutputResult(result)
		require.NoError(t, err)

		got, err := DeserializeRelinquishOutputResult(data)
		require.NoError(t, err)
		require.Equal(t, result, got)
	})
}
