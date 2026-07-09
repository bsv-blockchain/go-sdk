package serializer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/wallet"
)

func TestGetNetworkResult(t *testing.T) {
	tests := []struct {
		name   string
		result *wallet.GetNetworkResult
	}{
		{
			name: "mainnet",
			result: &wallet.GetNetworkResult{
				Network: wallet.NetworkMainnet,
			},
		},
		{
			name: "testnet",
			result: &wallet.GetNetworkResult{
				Network: wallet.NetworkTestnet,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeGetNetworkResult(tt.result)
			require.NoError(t, err)
			require.Len(t, data, 1) // error byte + network byte

			// Test deserialization
			got, err := DeserializeGetNetworkResult(data)
			require.NoError(t, err)
			require.Equal(t, tt.result, got)
		})
	}
}
