package serializer

import (
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestInternalizeActionArgs(t *testing.T) {
	pk, err := ec.NewPrivateKey()
	require.NoError(t, err, "creating new private key should not error")
	senderKey := pk.PubKey()
	testRef := "test-reference-123"
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
					Protocol:    wallet.InternalizeProtocolWalletPayment,
					PaymentRemittance: &wallet.Payment{
						DerivationPrefix:  []byte("prefix"),
						DerivationSuffix:  []byte("suffix"),
						SenderIdentityKey: senderKey,
					},
				},
				{
					OutputIndex: 1,
					Protocol:    wallet.InternalizeProtocolBasketInsertion,
					InsertionRemittance: &wallet.BasketInsertion{
						Basket:             "test-basket",
						CustomInstructions: "instructions",
						Tags:               []string{"tag1", "tag2"},
					},
				},
			},
			Description:    "test description",
			Labels:         []string{"label1", "label2"},
			SeekPermission: util.BoolPtr(true),
		},
	}, {
		name: "full args with reference",
		args: &wallet.InternalizeActionArgs{
			Tx: []byte{1, 2, 3, 4},
			Outputs: []wallet.InternalizeOutput{
				{
					OutputIndex: 0,
					Protocol:    wallet.InternalizeProtocolWalletPayment,
					PaymentRemittance: &wallet.Payment{
						DerivationPrefix:  []byte("prefix"),
						DerivationSuffix:  []byte("suffix"),
						SenderIdentityKey: senderKey,
					},
				},
			},
			Description:    "test description with reference",
			Labels:         []string{"label1"},
			SeekPermission: util.BoolPtr(true),
			Reference:      &testRef,
		},
	}, {
		name: "minimal args",
		args: &wallet.InternalizeActionArgs{
			Tx:          []byte{1},
			Description: "minimal",
			Outputs: []wallet.InternalizeOutput{
				{
					OutputIndex: 0,
					Protocol:    wallet.InternalizeProtocolWalletPayment,
					PaymentRemittance: &wallet.Payment{
						SenderIdentityKey: senderKey,
					},
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
			require.NoError(t, err, "serializing InternalizeActionArgs should not error")

			// Test deserialization
			got, err := DeserializeInternalizeActionArgs(data)
			require.NoError(t, err, "deserializing InternalizeActionArgs should not error")

			// Compare results
			require.Equal(t, tt.args, got, "deserialized args should match original args")
		})
	}
}

func TestInternalizeActionResult(t *testing.T) {
	t.Run("serialize/deserialize", func(t *testing.T) {
		result := &wallet.InternalizeActionResult{Accepted: true}
		data, err := SerializeInternalizeActionResult(result)
		require.NoError(t, err, "serializing InternalizeActionResult should not error")

		got, err := DeserializeInternalizeActionResult(data)
		require.NoError(t, err, "deserializing InternalizeActionResult should not error")
		require.Equal(t, result, got, "deserialized result should match original result")
	})
}
