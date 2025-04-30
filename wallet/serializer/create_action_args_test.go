package serializer

import (
	"math"
	"testing"

	"github.com/bsv-blockchain/go-sdk/util"
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
						LockingScript:      "76a9143cf53c49c322d9d811728182939aee2dca087f9888ac",
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
					SignAndProcess:         util.BoolPtr(true),
					AcceptDelayedBroadcast: util.BoolPtr(false),
					TrustSelf:              wallet.TrustSelfKnown,
					KnownTxids: []string{
						"8a552c995db3602e85bb9df911803897d1ea17ba5cdd198605d014be49db9f72",
						"490c292a700c55d5e62379828d60bf6c61850fbb4d13382f52021d3796221981",
					},
					ReturnTXIDOnly:   util.BoolPtr(true),
					NoSend:           util.BoolPtr(false),
					NoSendChange:     []string{"abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234.1"},
					SendWith:         []string{"b95bbe3c3f3bd420048cbf57201fc6dd4e730b2e046bf170ac0b1f78de069e8e"},
					RandomizeOutputs: util.BoolPtr(true),
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
						LockingScript: "76a9143cf53c49c322d9d811728182939aee2dca087f9888ac",
						Satoshis:      1000,
					},
				},
			},
		},
		{
			name: "with options only",
			args: &wallet.CreateActionArgs{
				Options: &wallet.CreateActionOptions{
					SignAndProcess: util.BoolPtr(true),
				},
			},
		},
		{
			name: "multiple inputs",
			args: &wallet.CreateActionArgs{
				Inputs: []wallet.CreateActionInput{
					{
						Outpoint:              "8a552c995db3602e85bb9df911803897d1ea17ba5cdd198605d014be49db9f72.0",
						InputDescription:      "input 1",
						UnlockingScript:       "abcd",
						UnlockingScriptLength: 2, // "abcd" is 2 bytes when decoded from hex
					},
					{
						Outpoint:              "490c292a700c55d5e62379828d60bf6c61850fbb4d13382f52021d3796221981.1",
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
						LockingScript:     "76a9143cf53c49c322d9d811728182939aee2dca087f9888ac",
						Satoshis:          1000,
						OutputDescription: "output 1",
					},
					{
						LockingScript:     "76a9143cf53c49c322d9d811728182939aee2dca087f9888ac",
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
			require.NoError(t, err, "serializing CreateActionArgs should not error")
			require.NotEmpty(t, data, "serialized data should not be empty")

			// Deserialize
			args, err := DeserializeCreateActionArgs(data)
			require.NoError(t, err, "deserializing CreateActionArgs should not error")

			// Compare
			require.Equal(t, tt.args, args, "deserialized args should match original args")
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
				w := util.NewWriter()
				// description (empty)
				w.WriteVarInt(0)
				// input BEEF (nil)
				w.WriteVarInt(math.MaxUint64)
				// inputs (1 item)
				w.WriteVarInt(1)
				// invalid outpoint (too short)
				w.WriteBytes([]byte{0x01, 0x02})
				return w.Buf
			}(),
			err: "error decoding outpoint: invalid outpoint data length",
		},
		{
			name: "invalid unlocking script",
			data: func() []byte {
				w := util.NewWriter()
				// description (empty)
				w.WriteVarInt(0)
				// input BEEF (nil)
				w.WriteVarInt(math.MaxUint64)
				// inputs (1 item)
				w.WriteVarInt(1)
				// valid outpoint
				w.WriteBytes(make([]byte, OutpointSize))
				// unlocking script length (invalid hex)
				w.WriteVarInt(2)
				w.WriteBytes([]byte{0x01, 0x02})
				return w.Buf
			}(),
			err: "error reading string length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeserializeCreateActionArgs(tt.data)
			require.Error(t, err, "deserializing invalid data should produce an error")
			require.Contains(t, err.Error(), tt.err, "error message should contain expected substring")
		})
	}
}
