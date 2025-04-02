package serializer

import (
	"math"
	"testing"

	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestCreateActionArgsSerializeAndDeserialize(t *testing.T) {
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
						SequenceNumber:        1,
					},
				},
				Outputs: []wallet.CreateActionOutput{
					{
						LockingScript:      "efef",
						Satoshis:           1000,
						OutputDescription:  "output 1",
						Basket:             "basket1",
						CustomInstructions: "custom1",
						Tags:               []string{"tag1", "tag2"},
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
		{
			name: "multiple inputs",
			args: &wallet.CreateActionArgs{
				Inputs: []wallet.CreateActionInput{
					{
						Outpoint:              "1111111111111111111111111111111111111111111111111111111111111111.0",
						InputDescription:      "input 1",
						UnlockingScript:       "abcd",
						UnlockingScriptLength: 2, // "abcd" is 2 bytes when decoded from hex
					},
					{
						Outpoint:              "2222222222222222222222222222222222222222222222222222222222222222.1",
						InputDescription:      "input 2",
						UnlockingScript:       "efef",
						UnlockingScriptLength: 2, // "efef" is 2 bytes when decoded from hex
						SequenceNumber:        2,
					},
				},
			},
		},
		{
			name: "multiple outputs",
			args: &wallet.CreateActionArgs{
				Outputs: []wallet.CreateActionOutput{
					{
						LockingScript:     "abcd",
						Satoshis:          1000,
						OutputDescription: "output 1",
					},
					{
						LockingScript:     "efef",
						Satoshis:          2000,
						OutputDescription: "output 2",
						Tags:              []string{"tag1", "tag2"},
					},
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
			require.Equal(t, tt.args, args)
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
				w := newWriter()
				// description (empty)
				w.writeVarInt(0)
				// input BEEF (nil)
				w.writeVarInt(math.MaxUint64)
				// inputs (1 item)
				w.writeVarInt(1)
				// invalid outpoint (too short)
				w.writeBytes([]byte{0x01, 0x02})
				return w.buf
			}(),
			err: "error decoding outpoint: invalid outpoint data length",
		},
		{
			name: "invalid unlocking script",
			data: func() []byte {
				w := newWriter()
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
				return w.buf
			}(),
			err: "error reading string length",
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
