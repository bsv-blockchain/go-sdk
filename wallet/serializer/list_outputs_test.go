package serializer

import (
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestListOutputsArgs(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.ListOutputsArgs
	}{
		{
			name: "full args",
			args: &wallet.ListOutputsArgs{
				Basket:                    "test-basket",
				Tags:                      []string{"tag1", "tag2"},
				TagQueryMode:              "any",
				Include:                   "entire transactions",
				IncludeCustomInstructions: util.BoolPtr(true),
				IncludeTags:               util.BoolPtr(true),
				IncludeLabels:             util.BoolPtr(false),
				Limit:                     100,
				Offset:                    10,
				SeekPermission:            util.BoolPtr(true),
			},
		},
		{
			name: "minimal args",
			args: &wallet.ListOutputsArgs{
				Basket: "minimal-basket",
				Limit:  10,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeListOutputsArgs(tt.args)
			require.NoError(t, err)

			// Test deserialization
			got, err := DeserializeListOutputsArgs(data)
			require.NoError(t, err)

			// Compare results
			require.Equal(t, tt.args, got)
		})
	}
}

func TestListOutputsResult(t *testing.T) {
	t.Run("with BEEF and outputs", func(t *testing.T) {
		result := &wallet.ListOutputsResult{
			TotalOutputs: 2,
			BEEF:         []byte{1, 2, 3, 4},
			Outputs: []wallet.Output{
				{
					Satoshis:           1000,
					LockingScript:      "76a9143cf53c49c322d9d811728182939aee2dca087f9888ac",
					Spendable:          true,
					CustomInstructions: "instructions",
					Tags:               []string{"tag1"},
					Outpoint:           "txid.0",
					Labels:             []string{"label1"},
				},
				{
					Satoshis:      2000,
					LockingScript: "76a9143cf53c49c322d9d811728182939aee2dca087f9888ad",
					Spendable:     false,
					Outpoint:      "txid.1",
				},
			},
		}

		data, err := SerializeListOutputsResult(result)
		require.NoError(t, err)

		got, err := DeserializeListOutputsResult(data)
		require.NoError(t, err)
		require.Equal(t, result, got)
	})

	t.Run("minimal result", func(t *testing.T) {
		result := &wallet.ListOutputsResult{
			TotalOutputs: 0,
			Outputs:      []wallet.Output{},
		}

		data, err := SerializeListOutputsResult(result)
		require.NoError(t, err)

		got, err := DeserializeListOutputsResult(data)
		require.NoError(t, err)
		require.Equal(t, result, got)
	})
}
