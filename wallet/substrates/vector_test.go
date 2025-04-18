package substrates_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/serializer"
	"github.com/bsv-blockchain/go-sdk/wallet/substrates"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

type VectorTest struct {
	Filename string
	Object   any
}

func base64ToBytes(t *testing.T, s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestVectors(t *testing.T) {
	// TODO: Add the rest of the test vector files
	tests := []VectorTest{{
		Filename: "abortAction-simple-args.json",
		Object: wallet.AbortActionArgs{
			Reference: base64ToBytes(t, "dGVzdA=="),
		},
	}, {
		Filename: "createAction-1-out-args.json",
		Object: wallet.CreateActionArgs{
			Description: "Test action description",
			Outputs: []wallet.CreateActionOutput{{
				LockingScript:      "76a9143cf53c49c322d9d811728182939aee2dca087f9888ac",
				Satoshis:           999,
				OutputDescription:  "Test output",
				Basket:             "test-basket",
				CustomInstructions: "Test instructions",
				Tags:               []string{"test-tag"},
			}},
			Labels: []string{"test-label"},
		},
	}}
	for _, tt := range tests {
		t.Run(tt.Filename, func(t *testing.T) {
			// Read test vector file
			data, err := os.ReadFile(filepath.Join("testdata", tt.Filename))
			if err != nil {
				t.Fatalf("Failed to read test file: %v", err)
			}

			// Parse test vector
			var vectorFile map[string]json.RawMessage
			if err := json.Unmarshal(data, &vectorFile); err != nil {
				t.Fatalf("Failed to parse test vector file: %v", err)
			} else if len(vectorFile["json"]) == 0 || len(vectorFile["wire"]) == 0 {
				t.Fatalf("Both json and wire format requried in test vector file")
			}
			var wireString string
			require.NoError(t, json.Unmarshal(vectorFile["wire"], &wireString))
			wire, err := hex.DecodeString(wireString)
			require.NoError(t, err)

			// Test JSON marshaling
			t.Run("JSON", func(t *testing.T) {
				// Define a function to check JSON serialization and deserialization
				checkJson := func(emptyObj, expectedObj any) {
					require.NoError(t, json.Unmarshal(vectorFile["json"], emptyObj))
					require.Equal(t, expectedObj, emptyObj)
					marshaled, err := json.MarshalIndent(expectedObj, "  ", "  ")
					require.NoError(t, err)
					require.Equal(t, string(vectorFile["json"]), string(marshaled))
				}

				// Marshal the object to JSON
				switch obj := tt.Object.(type) {
				case wallet.AbortActionArgs:
					var deserialized wallet.AbortActionArgs
					checkJson(&deserialized, &obj)
				case wallet.CreateActionArgs:
					var deserialized wallet.CreateActionArgs
					checkJson(&deserialized, &obj)
				default:
					t.Fatalf("Unsupported object type: %T", obj)
				}
			})

			// Test wire format serialization
			t.Run("Wire", func(t *testing.T) {
				frame, err := serializer.ReadRequestFrame(wire)
				require.NoError(t, err)

				// Define a function to check wire serialization and deserialization
				checkWireSerialize := func(call substrates.Call, obj any, serialized []byte, err1 error, deserialized any, err2 error) {
					require.Equal(t, frame.Call, byte(call))
					require.Equal(t, frame.Originator, "")
					require.NoError(t, err1)
					serializedWithFrame := serializer.WriteRequestFrame(serializer.RequestFrame{
						Call:   byte(call),
						Params: serialized,
					})
					require.Equal(t, wire, serializedWithFrame)
					require.NoError(t, err2)
					require.Equal(t, obj, deserialized)
				}

				// Marshal the object to JSON
				switch obj := tt.Object.(type) {
				case wallet.AbortActionArgs:
					serialized, err1 := serializer.SerializeAbortActionArgs(&obj)
					deserialized, err2 := serializer.DeserializeAbortActionArgs(frame.Params)
					checkWireSerialize(substrates.CallAbortAction, &obj, serialized, err1, deserialized, err2)
				case wallet.CreateActionArgs:
					serialized, err1 := serializer.SerializeCreateActionArgs(&obj)
					deserialized, err2 := serializer.DeserializeCreateActionArgs(wire)
					checkWireSerialize(substrates.CallCreateAction, &obj, serialized, err1, deserialized, err2)
				default:
					t.Fatalf("Unsupported object type: %T", obj)
				}
			})
		})
	}
}
