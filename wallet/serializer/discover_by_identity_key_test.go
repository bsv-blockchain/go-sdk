package serializer

import (
	"github.com/bsv-blockchain/go-sdk/util"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDiscoverByIdentityKeyArgs(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.DiscoverByIdentityKeyArgs
	}{{
		name: "full args",
		args: &wallet.DiscoverByIdentityKeyArgs{
			IdentityKey:    tu.GetByte33FromHexString(t, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
			Limit:          10,
			Offset:         5,
			SeekPermission: util.BoolPtr(true),
		},
	}, {
		name: "minimal args",
		args: &wallet.DiscoverByIdentityKeyArgs{
			IdentityKey: tu.GetByte33FromHexString(t, "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
		},
	}, {
		name: "undefined limit/offset",
		args: &wallet.DiscoverByIdentityKeyArgs{
			IdentityKey:    tu.GetByte33FromHexString(t, "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
			SeekPermission: util.BoolPtr(false),
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeDiscoverByIdentityKeyArgs(tt.args)
			require.NoError(t, err)

			// Test deserialization
			got, err := DeserializeDiscoverByIdentityKeyArgs(data)
			require.NoError(t, err)

			// Compare results
			require.Equal(t, tt.args, got)
		})
	}
}
