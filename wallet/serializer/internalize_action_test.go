package serializer

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestInternalizeActionArgs(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.InternalizeActionArgs
	}{{
		name: "full args",
		args: &wallet.InternalizeActionArgs{
			Tx: []byte{1, 2, 3, 4},
			Outputs: []wallet.InternalizeOutput{
				{
					OutputIndex: 0,
					Protocol:    "wallet payment",
					PaymentRemittance: &wallet.Payment{
						DerivationPrefix:  "prefix",
						DerivationSuffix:  "suffix",
						SenderIdentityKey: "sender-key",
					},
				},
				{
					OutputIndex: 1,
					Protocol:    "basket insertion",
					InsertionRemittance: &wallet.BasketInsertion{
						Basket:             "test-basket",
						CustomInstructions: "instructions",
						Tags:               []string{"tag1", "tag2"},
					},
				},
			},
			Description:    "test description",
			Labels:         []string{"label1", "label2"},
			SeekPermission: boolPtr(true),
		},
	}, {
		name: "minimal args",
		args: &wallet.InternalizeActionArgs{
			Tx:          []byte{1},
			Description: "minimal",
			Outputs: []wallet.InternalizeOutput{
				{
					OutputIndex: 0,
					Protocol:    "wallet payment",
				},
			},
		},
	}, {
		name: "empty tx",
		args: &wallet.InternalizeActionArgs{
			Tx:          []byte{},
			Description: "empty tx",
			Outputs:     []wallet.InternalizeOutput{},
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeInternalizeActionArgs(tt.args)
			require.NoError(t, err)

			// Test deserialization
			got, err := DeserializeInternalizeActionArgs(data)
			require.NoError(t, err)

			// Compare results
			require.Equal(t, tt.args, got)
		})
	}
}

func TestInternalizeActionResult(t *testing.T) {
	t.Run("serialize/deserialize", func(t *testing.T) {
		result := &wallet.InternalizeActionResult{Accepted: true}
		data, err := SerializeInternalizeActionResult(result)
		require.NoError(t, err)

		got, err := DeserializeInternalizeActionResult(data)
		require.NoError(t, err)
		require.Equal(t, result, got)
	})
}
