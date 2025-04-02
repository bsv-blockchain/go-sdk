package serializer

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
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
				IncludeLabels:                    boolPtr(true),
				IncludeInputs:                    boolPtr(false),
				IncludeInputSourceLockingScripts: boolPtr(true),
				IncludeInputUnlockingScripts:     boolPtr(false),
				IncludeOutputs:                   boolPtr(true),
				IncludeOutputLockingScripts:      boolPtr(false),
				Limit:                            100,
				Offset:                           10,
				SeekPermission:                   boolPtr(false),
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
			if (err != nil) != tt.wantErr {
				t.Errorf("SerializeListActionsArgs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Test deserialization
			deserialized, err := DeserializeListActionsArgs(data)
			if err != nil {
				t.Errorf("DeserializeListActionsArgs() error = %v", err)
				return
			}

			// Compare original and deserialized
			assert.Equal(t, tt.args, *deserialized)
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
			if (err != nil) != tt.wantErr {
				t.Errorf("SerializeListActionsResult() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Test deserialization
			deserialized, err := DeserializeListActionsResult(data)
			if err != nil {
				t.Errorf("DeserializeListActionsResult() error = %v", err)
				return
			}

			// Compare original and deserialized
			assert.Equal(t, tt.result, *deserialized)
		})
	}
}
