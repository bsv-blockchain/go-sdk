package serializer

import (
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDiscoverByAttributesArgs(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.DiscoverByAttributesArgs
	}{{
		name: "full args",
		args: &wallet.DiscoverByAttributesArgs{
			Attributes: map[string]string{
				"field1": "value1",
				"field2": "value2",
			},
			Limit:          10,
			Offset:         5,
			SeekPermission: util.BoolPtr(true),
		},
	}, {
		name: "minimal args",
		args: &wallet.DiscoverByAttributesArgs{
			Attributes: map[string]string{
				"field1": "value1",
			},
		},
	}, {
		name: "undefined limit/offset",
		args: &wallet.DiscoverByAttributesArgs{
			Attributes: map[string]string{
				"field1": "value1",
			},
			SeekPermission: util.BoolPtr(false),
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeDiscoverByAttributesArgs(tt.args)
			require.NoError(t, err)

			// Test deserialization
			got, err := DeserializeDiscoverByAttributesArgs(data)
			require.NoError(t, err)

			// Compare results
			require.Equal(t, tt.args, got)
		})
	}
}
