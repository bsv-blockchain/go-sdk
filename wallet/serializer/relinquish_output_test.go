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
				Output: "8a552c995db3602e85bb9df911803897d1ea17ba5cdd198605d014be49db9f72.0",
			},
		},
		{
			name: "empty basket",
			args: &wallet.RelinquishOutputArgs{
				Basket: "",
				Output: "8a552c995db3602e85bb9df911803897d1ea17ba5cdd198605d014be49db9f72.1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeRelinquishOutputArgs(tt.args)
			require.NoError(t, err, "serializing RelinquishOutputArgs should not error")

			// Test deserialization
			got, err := DeserializeRelinquishOutputArgs(data)
			require.NoError(t, err, "deserializing RelinquishOutputArgs should not error")

			// Compare results
			require.Equal(t, tt.args, got, "deserialized args should match original args")
		})
	}
}

func TestRelinquishOutputResult(t *testing.T) {
	t.Run("successful relinquish", func(t *testing.T) {
		result := &wallet.RelinquishOutputResult{Relinquished: true}
		data, err := SerializeRelinquishOutputResult(result)
		require.NoError(t, err, "serializing successful RelinquishOutputResult should not error")

		got, err := DeserializeRelinquishOutputResult(data)
		require.NoError(t, err, "deserializing successful RelinquishOutputResult should not error")
		require.Equal(t, result, got, "deserialized successful result should match original")
	})

	t.Run("failed relinquish", func(t *testing.T) {
		result := &wallet.RelinquishOutputResult{Relinquished: false}
		data, err := SerializeRelinquishOutputResult(result)
		require.NoError(t, err, "serializing failed RelinquishOutputResult should not error")

		got, err := DeserializeRelinquishOutputResult(data)
		require.NoError(t, err, "deserializing failed RelinquishOutputResult should not error")
		require.Equal(t, result, got, "deserialized failed result should match original")
	})
}
