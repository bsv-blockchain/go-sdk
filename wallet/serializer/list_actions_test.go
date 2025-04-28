package serializer

import (
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestListActionArgsSerializeAndDeserialize(t *testing.T) {
	tests := []struct {
		name    string
		args    wallet.ListActionsArgs
		wantErr bool
	}{
		{
			name: "full args",
			args: wallet.ListActionsArgs{
				Labels:                           []string{"label1", "label2"},
				LabelQueryMode:                   "all",
				IncludeLabels:                    util.BoolPtr(true),
				IncludeInputs:                    util.BoolPtr(false),
				IncludeInputSourceLockingScripts: util.BoolPtr(true),
				IncludeInputUnlockingScripts:     util.BoolPtr(false),
				IncludeOutputs:                   util.BoolPtr(true),
				IncludeOutputLockingScripts:      util.BoolPtr(false),
				Limit:                            100,
				Offset:                           10,
				SeekPermission:                   util.BoolPtr(false),
			},
			wantErr: false,
		},
		{
			name: "minimal args",
			args: wallet.ListActionsArgs{
				Labels: []string{"label1"},
			},
			wantErr: false,
		},
		{
			name: "empty labels",
			args: wallet.ListActionsArgs{
				Labels: []string{},
			},
			wantErr: false,
		},
		{
			name: "nil options",
			args: wallet.ListActionsArgs{
				Labels:                           []string{"label1"},
				LabelQueryMode:                   "",
				IncludeLabels:                    nil,
				IncludeInputs:                    nil,
				IncludeInputSourceLockingScripts: nil,
				IncludeInputUnlockingScripts:     nil,
				IncludeOutputs:                   nil,
				IncludeOutputLockingScripts:      nil,
				Limit:                            0,
				Offset:                           0,
				SeekPermission:                   nil,
			},
			wantErr: false,
		},
		{
			name: "invalid label query mode",
			args: wallet.ListActionsArgs{
				Labels:         []string{"label1"},
				LabelQueryMode: "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeListActionsArgs(&tt.args)
			if tt.wantErr {
				require.Error(t, err, "serializing with invalid args should error")
				return
			}
			require.NoError(t, err, "serializing valid ListActionsArgs should not error")

			// Test deserialization
			deserialized, err := DeserializeListActionsArgs(data)
			require.NoError(t, err, "deserializing valid ListActionsArgs should not error")

			// Compare original and deserialized
			assert.Equal(t, tt.args, *deserialized, "deserialized args should match original args")
		})
	}
}

func TestListActionResultSerializeAndDeserialize(t *testing.T) {
	txid := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

	tests := []struct {
		name    string
		result  wallet.ListActionsResult
		wantErr bool
	}{
		{
			name: "full result",
			result: wallet.ListActionsResult{
				TotalActions: 2,
				Actions: []wallet.Action{
					{
						Txid:        txid,
						Satoshis:    1000,
						Status:      "completed",
						IsOutgoing:  true,
						Description: "test action 1",
						Labels:      []string{"label1", "label2"},
						Version:     1,
						LockTime:    0,
						Inputs: []wallet.ActionInput{
							{
								SourceOutpoint:      txid + ".0",
								SourceSatoshis:      500,
								SourceLockingScript: "76a914abcdef88ac",
								UnlockingScript:     "483045022100abcdef",
								InputDescription:    "input 1",
								SequenceNumber:      0xffffffff,
							},
						},
						Outputs: []wallet.ActionOutput{
							{
								OutputIndex:        0,
								Satoshis:           1000,
								LockingScript:      "76a914abcdef88ac",
								Spendable:          true,
								OutputDescription:  "output 1",
								Basket:             "basket1",
								Tags:               []string{"tag1"},
								CustomInstructions: "instructions1",
							},
						},
					},
					{
						Txid:        txid,
						Satoshis:    2000,
						Status:      "sending",
						IsOutgoing:  false,
						Description: "test action 2",
						Labels:      []string{"label3"},
						Version:     1,
						LockTime:    123456,
						Inputs:      []wallet.ActionInput{},
						Outputs:     []wallet.ActionOutput{},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "empty result",
			result: wallet.ListActionsResult{
				TotalActions: 0,
				Actions:      []wallet.Action{},
			},
			wantErr: false,
		},
		{
			name: "invalid txid",
			result: wallet.ListActionsResult{
				TotalActions: 1,
				Actions: []wallet.Action{
					{
						Txid: "invalid",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid status",
			result: wallet.ListActionsResult{
				TotalActions: 1,
				Actions: []wallet.Action{
					{
						Txid:   txid,
						Status: "invalid",
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeListActionsResult(&tt.result)
			if tt.wantErr {
				require.Error(t, err, "serializing with invalid result data should error")
				return
			}
			require.NoError(t, err, "serializing valid ListActionsResult should not error")

			// Test deserialization
			deserialized, err := DeserializeListActionsResult(data)
			require.NoError(t, err, "deserializing valid ListActionsResult should not error")

			// Compare original and deserialized
			assert.Equal(t, tt.result, *deserialized, "deserialized result should match original result")
		})
	}
}
