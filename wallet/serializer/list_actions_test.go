package serializer

import (
	"encoding/hex"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/util"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

type ListActionArgsSerializeTest struct {
	name string
	args wallet.ListActionsArgs
}

func TestListActionArgsSerializeAndDeserialize(t *testing.T) {
	tests := []ListActionArgsSerializeTest{
		{
			name: "full args",
			args: wallet.ListActionsArgs{
				Labels:                           []string{"label1", "label2"},
				LabelQueryMode:                   wallet.QueryModeAll,
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
		},
		{
			name: "minimal args",
			args: wallet.ListActionsArgs{
				Labels: []string{"label1"},
			},
		},
		{
			name: "empty labels",
			args: wallet.ListActionsArgs{
				Labels: []string{},
			},
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
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeListActionsArgs(&tt.args)
			require.NoError(t, err, "serializing valid ListActionsArgs should not error")

			// Test deserialization
			deserialized, err := DeserializeListActionsArgs(data)
			require.NoError(t, err, "deserializing valid ListActionsArgs should not error")

			// Compare original and deserialized
			assert.Equal(t, tt.args, *deserialized, "deserialized args should match original args")
		})
	}
}

func TestListActionArgsSerializeAndDeserializeError(t *testing.T) {
	tests := []ListActionArgsSerializeTest{{
		name: "invalid label query mode",
		args: wallet.ListActionsArgs{
			Labels:         []string{"label1"},
			LabelQueryMode: "invalid",
		},
	}, {
		name: "invalid label query mode",
		args: wallet.ListActionsArgs{
			Labels:         []string{"label1"},
			LabelQueryMode: "invalid",
			Limit:          100000,
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization fails
			_, err := SerializeListActionsArgs(&tt.args)
			require.Error(t, err, "serializing with invalid args should error")
		})
	}
}

type ListActionResultSerializeTest struct {
	name   string
	result wallet.ListActionsResult
}

func TestListActionResultSerializeAndDeserialize(t *testing.T) {
	txid, err := chainhash.NewHashFromHex("b1f4d452814bba0ac422318083850b706d5f23ce232c789eefe5cbdcf2cc47de")
	require.NoError(t, err, "creating txid from hex should not error")
	lockingScript, err := hex.DecodeString("76a914abcdef88ac")
	require.NoError(t, err, "decoding locking script should not error")
	unlockingScript, err := hex.DecodeString("483045022100abcdef")
	require.NoError(t, err, "decoding unlocking script should not error")

	tests := []ListActionResultSerializeTest{
		{
			name: "full result",
			result: wallet.ListActionsResult{
				TotalActions: 2,
				Actions: []wallet.Action{
					{
						Txid:        *txid,
						Satoshis:    1000,
						Status:      "completed",
						IsOutgoing:  true,
						Description: "test action 1",
						Labels:      []string{"label1", "label2"},
						Version:     1,
						LockTime:    0,
						Inputs: []wallet.ActionInput{
							{
								SourceOutpoint:      wallet.Outpoint{Txid: *txid},
								SourceSatoshis:      500,
								SourceLockingScript: lockingScript,
								UnlockingScript:     unlockingScript,
								InputDescription:    "input 1",
								SequenceNumber:      0xffffffff,
							},
						},
						Outputs: []wallet.ActionOutput{
							{
								OutputIndex:        0,
								Satoshis:           1000,
								LockingScript:      lockingScript,
								Spendable:          true,
								OutputDescription:  "output 1",
								Basket:             "basket1",
								Tags:               []string{"tag1"},
								CustomInstructions: "instructions1",
							},
						},
					},
					{
						Txid:        *txid,
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
		},
		{
			name: "empty result",
			result: wallet.ListActionsResult{
				TotalActions: 0,
				Actions:      []wallet.Action{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeListActionsResult(&tt.result)
			require.NoError(t, err, "serializing valid ListActionsResult should not error")

			// Test deserialization
			deserialized, err := DeserializeListActionsResult(data)
			require.NoError(t, err, "deserializing valid ListActionsResult should not error")

			// Compare original and deserialized
			assert.Equal(t, tt.result, *deserialized, "deserialized result should match original result")
		})
	}
}

func TestListActionResultSerializeAndDeserializeError(t *testing.T) {
	txid := tu.GetByte32FromHexString(t, "912e0a97a189347a94f634a6eb4d67e13df9afc8fea670287b31d277e8d658d8")
	tests := []ListActionResultSerializeTest{
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
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			_, err := SerializeListActionsResult(&tt.result)
			require.Error(t, err, "serializing with invalid result data should error")
		})
	}
}
