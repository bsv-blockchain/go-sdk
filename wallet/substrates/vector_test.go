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
	IsResult bool
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
		Filename: "abortAction-simple-args",
		Object: wallet.AbortActionArgs{
			Reference: base64ToBytes(t, "dGVzdA=="),
		},
	}, {
		Filename: "abortAction-simple-result",
		IsResult: true,
		Object: wallet.AbortActionResult{
			Aborted: true,
		},
	}, {
		// TODO: This test is failing, I think also because of how ts-sdk handles -1
		Filename: "signAction-simple-args",
		Object: wallet.SignActionArgs{
			Reference: "dGVzdA==",
			Spends: map[uint32]wallet.SignActionSpend{
				0: {
					UnlockingScript: "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac",
				},
			},
		},
	}, {
		// TODO: This test is failing because of issues with how ts-sdk encodes/decodes -1
		Filename: "createAction-1-out-args",
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
	}, /*{
		Filename: "listActions-simple-args",
		IsResult: true,
		Object: wallet.ListActionsArgs{
			Labels:         []string{"test-label"},
			Limit:          10,
			IncludeOutputs: util.BoolPtr(true),
		},
	}, {
		Filename: "listActions-simple-results",
		IsResult: true,
		Object: wallet.ListActionsResult{
			TotalActions: 2,
			Actions: []wallet.Action{{
				Txid:        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				Satoshis:    1000,
				Status:      wallet.ActionStatusCompleted,
				IsOutgoing:  true,
				Description: "Test transaction 1",
				Version:     1,
				LockTime:    10,
				Outputs: []wallet.ActionOutput{{
					OutputIndex:       1,
					OutputDescription: "Test output",
					Basket:            "basket1",
					Spendable:         true,
					Tags:              []string{"tag1", "tag2"},
					Satoshis:          1000,
					LockingScript:     "76a9143cf53c49c322d9d811728182939aee2dca087f9888ac",
				}},
			}, {
				Status:  wallet.ActionStatusUnsigned,
				Outputs: []wallet.ActionOutput{{}},
			}},
		},
	}*/}
	for _, tt := range tests {
		t.Run(tt.Filename, func(t *testing.T) {
			// Read test vector file
			data, err := os.ReadFile(filepath.Join("testdata", tt.Filename+".json"))
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
				case wallet.SignActionArgs:
					var deserialized wallet.SignActionArgs
					checkJson(&deserialized, &obj)
				case wallet.AbortActionResult:
					var deserialized wallet.AbortActionResult
					checkJson(&deserialized, &obj)
				default:
					t.Fatalf("Unsupported object type: %T", obj)
				}
			})

			// Test wire format serialization
			t.Run("Wire", func(t *testing.T) {
				var frameCall substrates.Call
				var frameParams []byte
				if tt.IsResult {
					frame, err := serializer.ReadResultFrame(wire)
					require.NoError(t, err)
					frameParams = frame
				} else {
					frame, err := serializer.ReadRequestFrame(wire)
					require.NoError(t, err)
					frameCall = substrates.Call(frame.Call)
					require.Equal(t, frame.Originator, "")
					frameParams = frame.Params
				}

				// Define a function to check wire serialization and deserialization
				checkWireSerialize := func(call substrates.Call, obj any, serialized []byte, err1 error, deserialized any, err2 error) {
					require.Equal(t, frameCall, call)
					require.NoError(t, err1)
					var serializedWithFrame []byte
					if tt.IsResult {
						serializedWithFrame = serialized
					} else {
						serializedWithFrame = serializer.WriteRequestFrame(serializer.RequestFrame{
							Call:   byte(call),
							Params: serialized,
						})
					}
					require.Equal(t, wire, serializedWithFrame)
					require.NoError(t, err2)
					require.Equal(t, obj, deserialized)
				}

				// Marshal the object to JSON
				switch obj := tt.Object.(type) {
				case wallet.AbortActionArgs:
					serialized, err1 := serializer.SerializeAbortActionArgs(&obj)
					deserialized, err2 := serializer.DeserializeAbortActionArgs(frameParams)
					checkWireSerialize(substrates.CallAbortAction, &obj, serialized, err1, deserialized, err2)
				case wallet.CreateActionArgs:
					serialized, err1 := serializer.SerializeCreateActionArgs(&obj)
					deserialized, err2 := serializer.DeserializeCreateActionArgs(frameParams)
					checkWireSerialize(substrates.CallCreateAction, &obj, serialized, err1, deserialized, err2)
				case wallet.AbortActionResult:
					serialized, err1 := serializer.SerializeAbortActionResult(&obj)
					deserialized, err2 := serializer.DeserializeAbortActionResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.SignActionArgs:
					serialized, err1 := serializer.SerializeSignActionArgs(&obj)
					deserialized, err2 := serializer.DeserializeSignActionArgs(frameParams)
					checkWireSerialize(substrates.CallSignAction, &obj, serialized, err1, deserialized, err2)
				default:
					t.Fatalf("Unsupported object type: %T", obj)
				}
			})
		})
	}
}
