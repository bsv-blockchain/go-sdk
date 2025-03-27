package serializer

import (
	"math"
	"testing"

	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestCreateActionArgsRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.CreateActionArgs
	}{
		{
			name: "full args",
			args: &wallet.CreateActionArgs{
				Description: "test transaction",
				InputBEEF:   []byte{0x01, 0x02, 0x03},
				Inputs: []wallet.CreateActionInput{
					{
						Outpoint:              "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234.0",
						InputDescription:      "input 1",
						UnlockingScript:       "abcd",
						UnlockingScriptLength: 2, // Length is in bytes, "abcd" is 2 bytes when decoded from hex
						SequenceNumber:       1,
					},
				},
				Outputs: []wallet.CreateActionOutput{
					{
						LockingScript:      "efef",
						Satoshis:          1000,
						OutputDescription: "output 1",
						Basket:            "basket1",
						CustomInstructions: "custom1",
						Tags:              []string{"tag1", "tag2"},
					},
				},
				LockTime: 100,
				Version:  1,
				Labels:   []string{"label1", "label2"},
				Options: &wallet.CreateActionOptions{
					SignAndProcess:         boolPtr(true),
					AcceptDelayedBroadcast: boolPtr(false),
					TrustSelf:              "known",
					KnownTxids: []string{
						"1111111111111111111111111111111111111111111111111111111111111111",
						"2222222222222222222222222222222222222222222222222222222222222222",
					},
					ReturnTXIDOnly:   boolPtr(true),
					NoSend:           boolPtr(false),
					NoSendChange:     []string{"abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234.1"},
					SendWith:         []string{"3333333333333333333333333333333333333333333333333333333333333333"},
					RandomizeOutputs: boolPtr(true),
				},
			},
		},
		{
			name: "minimal args",
			args: &wallet.CreateActionArgs{},
		},
		{
			name: "with inputs only",
			args: &wallet.CreateActionArgs{
				Inputs: []wallet.CreateActionInput{
					{
						Outpoint:         "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234.0",
						InputDescription: "input 1",
					},
				},
			},
		},
		{
			name: "with outputs only",
			args: &wallet.CreateActionArgs{
				Outputs: []wallet.CreateActionOutput{
					{
						LockingScript: "abcd",
						Satoshis:      1000,
					},
				},
			},
		},
		{
			name: "with options only",
			args: &wallet.CreateActionArgs{
				Options: &wallet.CreateActionOptions{
					SignAndProcess: boolPtr(true),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Serialize
			data, err := SerializeCreateActionArgs(tt.args)
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Deserialize
			args, err := DeserializeCreateActionArgs(data)
			require.NoError(t, err)

			// Compare
			require.Equal(t, tt.args.Description, args.Description)
			require.Equal(t, tt.args.InputBEEF, args.InputBEEF)

			if tt.args.Inputs != nil {
				require.Equal(t, len(tt.args.Inputs), len(args.Inputs))
				for i := range tt.args.Inputs {
					require.Equal(t, tt.args.Inputs[i].Outpoint, args.Inputs[i].Outpoint)
					require.Equal(t, tt.args.Inputs[i].InputDescription, args.Inputs[i].InputDescription)
					require.Equal(t, tt.args.Inputs[i].UnlockingScript, args.Inputs[i].UnlockingScript)
					require.Equal(t, tt.args.Inputs[i].UnlockingScriptLength, args.Inputs[i].UnlockingScriptLength)
					require.Equal(t, tt.args.Inputs[i].SequenceNumber, args.Inputs[i].SequenceNumber)
				}
			} else {
				require.Nil(t, args.Inputs)
			}

			if tt.args.Outputs != nil {
				require.Equal(t, len(tt.args.Outputs), len(args.Outputs))
				for i := range tt.args.Outputs {
					require.Equal(t, tt.args.Outputs[i].LockingScript, args.Outputs[i].LockingScript)
					require.Equal(t, tt.args.Outputs[i].Satoshis, args.Outputs[i].Satoshis)
					require.Equal(t, tt.args.Outputs[i].OutputDescription, args.Outputs[i].OutputDescription)
					require.Equal(t, tt.args.Outputs[i].Basket, args.Outputs[i].Basket)
					require.Equal(t, tt.args.Outputs[i].CustomInstructions, args.Outputs[i].CustomInstructions)
					require.Equal(t, tt.args.Outputs[i].Tags, args.Outputs[i].Tags)
				}
			} else {
				require.Nil(t, args.Outputs)
			}

			require.Equal(t, tt.args.LockTime, args.LockTime)
			require.Equal(t, tt.args.Version, args.Version)
			require.Equal(t, tt.args.Labels, args.Labels)

			if tt.args.Options != nil {
				require.NotNil(t, args.Options)
				require.Equal(t, tt.args.Options.SignAndProcess, args.Options.SignAndProcess)
				require.Equal(t, tt.args.Options.AcceptDelayedBroadcast, args.Options.AcceptDelayedBroadcast)
				require.Equal(t, tt.args.Options.TrustSelf, args.Options.TrustSelf)
				require.Equal(t, tt.args.Options.KnownTxids, args.Options.KnownTxids)
				require.Equal(t, tt.args.Options.ReturnTXIDOnly, args.Options.ReturnTXIDOnly)
				require.Equal(t, tt.args.Options.NoSend, args.Options.NoSend)
				require.Equal(t, tt.args.Options.NoSendChange, args.Options.NoSendChange)
				require.Equal(t, tt.args.Options.SendWith, args.Options.SendWith)
				require.Equal(t, tt.args.Options.RandomizeOutputs, args.Options.RandomizeOutputs)
			} else {
				require.Nil(t, args.Options)
			}
		})
	}
}

func TestDeserializeCreateActionArgsErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		err  string
	}{
		{
			name: "empty data",
			data: []byte{},
			err:  "empty message",
		},
		{
			name: "invalid outpoint",
			data: func() []byte {
				w := newWriter(nil)
				// description (empty)
				w.writeVarInt(0)
				// input BEEF (nil)
				w.writeVarInt(math.MaxUint64)
				// inputs (1 item)
				w.writeVarInt(1)
				// invalid outpoint (too short)
				w.writeBytes([]byte{0x01, 0x02})
				return *w.buf
			}(),
			err: "invalid outpoint data length",
		},
		{
			name: "invalid unlocking script",
			data: func() []byte {
				w := newWriter(nil)
				// description (empty)
				w.writeVarInt(0)
				// input BEEF (nil)
				w.writeVarInt(math.MaxUint64)
				// inputs (1 item)
				w.writeVarInt(1)
				// valid outpoint
				w.writeBytes(make([]byte, 36))
				// unlocking script length (invalid hex)
				w.writeVarInt(2)
				w.writeBytes([]byte{0x01, 0x02})
				return *w.buf
			}(),
			err: "error decoding unlocking script",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeserializeCreateActionArgs(tt.data)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.err)
		})
	}
}

func boolPtr(b bool) *bool {
	return &b
}
