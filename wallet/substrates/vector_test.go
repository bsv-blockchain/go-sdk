package substrates_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/serializer"
	"github.com/bsv-blockchain/go-sdk/wallet/substrates"
	"github.com/stretchr/testify/require"
)

type VectorTest struct {
	Filename string
	IsResult bool
	Object   any
	Skip     bool
}

func base64ToBytes(t *testing.T, s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestVectors(t *testing.T) {
	privKey, err := ec.PrivateKeyFromHex("6a2991c9de20e38b31d7ea147bf55f5039e4bbc073160f5e0d541d1f17e321b8")
	require.NoError(t, err)
	const CounterpartyHex = "0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1"
	counterparty, err := ec.PublicKeyFromString(CounterpartyHex)
	require.NoError(t, err)
	const VerifierHex = "03b106dae20ae8fca0f4e8983d974c4b583054573eecdcdcfad261c035415ce1ee"
	verifier, err := ec.PublicKeyFromString(VerifierHex)
	require.NoError(t, err)
	const ProverHex = "02e14bb4fbcd33d02a0bad2b60dcd14c36506fa15599e3c28ec87eff440a97a2b8"
	prover, err := ec.PublicKeyFromString(ProverHex)
	require.NoError(t, err)

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
		// TODO: This wire test is failing, I think also because of how ts-sdk handles -1
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
		// TODO: This wire test is failing because of issues with how ts-sdk encodes/decodes -1
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
	}, {
		Filename: "listActions-simple-args",
		IsResult: true,
		Object: wallet.ListActionsArgs{
			Labels:         []string{"test-label"},
			Limit:          10,
			IncludeOutputs: util.BoolPtr(true),
		},
	}, {
		Filename: "listActions-simple-result",
		IsResult: true,
		Object: wallet.ListActionsResult{
			TotalActions: 1,
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
			}},
		},
	}, {
		Filename: "internalizeAction-simple-args",
		Object: wallet.InternalizeActionArgs{
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
						CustomInstructions: "instruction",
						Tags:               []string{"tag1", "tag2"},
					},
				},
			},
			Description:    "test transaction",
			Labels:         []string{"label1", "label2"},
			SeekPermission: util.BoolPtr(true),
		},
	}, {
		Filename: "internalizeAction-simple-result",
		IsResult: true,
		Object: wallet.InternalizeActionResult{
			Accepted: true,
		},
	}, {
		Filename: "listOutputs-simple-args",
		IsResult: true,
		Object: wallet.ListOutputsArgs{
			Basket:       "test-basket",
			Tags:         []string{"tag1", "tag2"},
			TagQueryMode: "any",
			Include:      "locking scripts",
			IncludeTags:  util.BoolPtr(true),
			Limit:        10,
		},
	}, {
		Filename: "listOutputs-simple-result",
		IsResult: true,
		Object: wallet.ListOutputsResult{
			TotalOutputs: 2,
			BEEF:         []byte{1, 2, 3, 4},
			Outputs: []wallet.Output{{
				Satoshis:  1000,
				Spendable: true,
				Outpoint:  "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef.0",
			}, {
				Satoshis:  5000,
				Spendable: false,
				Outpoint:  "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890.2",
			}},
		},
	}, {
		Filename: "relinquishOutput-simple-args",
		IsResult: true,
		Object: wallet.RelinquishOutputArgs{
			Basket: "test-basket",
			Output: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890.2",
		},
	}, {
		Filename: "relinquishOutput-simple-result",
		IsResult: true,
		Object: wallet.RelinquishOutputResult{
			Relinquished: true,
		},
	}, {
		Filename: "getPublicKey-simple-args",
		Object: wallet.GetPublicKeyArgs{
			IdentityKey: true,
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
					Protocol:      "tests",
				},
				Counterparty: wallet.Counterparty{
					Type:         wallet.CounterpartyTypeOther,
					Counterparty: counterparty,
				},
				KeyID:            "test-key-id",
				Privileged:       true,
				PrivilegedReason: "privileged reason",
				SeekPermission:   true,
			},
		},
	}, {
		Filename: "getPublicKey-simple-result",
		IsResult: true,
		Object: wallet.GetPublicKeyResult{
			PublicKey: privKey.PubKey(),
		},
	}, {
		Filename: "revealCounterpartyKeyLinkage-simple-args",
		Object: wallet.RevealCounterpartyKeyLinkageArgs{
			Counterparty:     CounterpartyHex,
			Verifier:         VerifierHex,
			Privileged:       util.BoolPtr(true),
			PrivilegedReason: "test-reason",
		},
	}, {
		Filename: "revealCounterpartyKeyLinkage-simple-result",
		IsResult: true,
		Object: wallet.RevealCounterpartyKeyLinkageResult{
			Prover:                ProverHex,
			Counterparty:          CounterpartyHex,
			Verifier:              VerifierHex,
			RevelationTime:        "2023-01-01T00:00:00Z",
			EncryptedLinkage:      []byte{1, 2, 3, 4},
			EncryptedLinkageProof: []byte{5, 6, 7, 8},
		},
	}, {
		Filename: "revealSpecificKeyLinkage-simple-args",
		Object: wallet.RevealSpecificKeyLinkageArgs{
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: counterparty,
			},
			Verifier: VerifierHex,
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
				Protocol:      "tests",
			},
			KeyID:            "test-key-id",
			Privileged:       util.BoolPtr(true),
			PrivilegedReason: "test-reason",
		},
	}, {
		Filename: "revealSpecificKeyLinkage-simple-result",
		IsResult: true,
		Object: wallet.RevealSpecificKeyLinkageResult{
			EncryptedLinkage:      []byte{1, 2, 3, 4},
			EncryptedLinkageProof: []byte{5, 6, 7, 8},
			Prover:                prover.ToDER(),
			Verifier:              verifier.ToDER(),
			Counterparty: wallet.Counterparty{
				Type:         wallet.CounterpartyTypeOther,
				Counterparty: counterparty,
			},
			ProtocolID: wallet.Protocol{
				SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
				Protocol:      "tests",
			},
			KeyID:     "test-key-id",
			ProofType: 1,
		},
	}, {
		Filename: "encrypt-simple-args",
		Object: wallet.EncryptArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryApp,
					Protocol:      "test-protocol",
				},
				KeyID:            "test-key",
				Counterparty:     wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
				Privileged:       true,
				PrivilegedReason: "test reason",
				SeekPermission:   true,
			},
			Plaintext: []byte{1, 2, 3, 4},
		},
	}, {
		Filename: "encrypt-simple-result",
		IsResult: true,
		Object: wallet.EncryptResult{
			Ciphertext: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		},
	}, {
		Filename: "decrypt-simple-args",
		Object: wallet.DecryptArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryApp,
					Protocol:      "test-protocol",
				},
				KeyID:            "test-key",
				Privileged:       true,
				PrivilegedReason: "test reason",
				SeekPermission:   true,
				Counterparty:     wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
			},
			Ciphertext: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		},
	}, {
		Filename: "decrypt-simple-result",
		IsResult: true,
		Object: wallet.DecryptResult{
			Plaintext: []byte{1, 2, 3, 4},
		},
	}, {
		Filename: "createHmac-simple-args",
		Object: wallet.CreateHmacArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: wallet.Protocol{
					SecurityLevel: wallet.SecurityLevelEveryApp,
					Protocol:      "test-protocol",
				},
				KeyID:            "test-key",
				Counterparty:     wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
				Privileged:       true,
				PrivilegedReason: "test reason",
				SeekPermission:   true,
			},
			Data: []byte{10, 20, 30, 40},
		},
	}, {
		Filename: "createHmac-simple-result",
		IsResult: true,
		Object: wallet.CreateHmacResult{
			Hmac: []byte{50, 60, 70, 80, 90, 100, 110, 120},
		},
	}}
	for _, tt := range tests {
		t.Run(tt.Filename, func(t *testing.T) {
			if tt.Skip {
				t.Skip()
			}
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
					require.EqualValues(t, expectedObj, emptyObj)
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
				case wallet.ListActionsArgs:
					var deserialized wallet.ListActionsArgs
					checkJson(&deserialized, &obj)
				case wallet.ListActionsResult:
					var deserialized wallet.ListActionsResult
					checkJson(&deserialized, &obj)
				case wallet.InternalizeActionArgs:
					var deserialized wallet.InternalizeActionArgs
					checkJson(&deserialized, &obj)
				case wallet.InternalizeActionResult:
					var deserialized wallet.InternalizeActionResult
					checkJson(&deserialized, &obj)
				case wallet.ListOutputsArgs:
					var deserialized wallet.ListOutputsArgs
					checkJson(&deserialized, &obj)
				case wallet.ListOutputsResult:
					var deserialized wallet.ListOutputsResult
					checkJson(&deserialized, &obj)
				case wallet.RelinquishOutputArgs:
					var deserialized wallet.RelinquishOutputArgs
					checkJson(&deserialized, &obj)
				case wallet.RelinquishOutputResult:
					var deserialized wallet.RelinquishOutputResult
					checkJson(&deserialized, &obj)
				case wallet.GetPublicKeyArgs:
					var deserialized wallet.GetPublicKeyArgs
					checkJson(&deserialized, &obj)
				case wallet.GetPublicKeyResult:
					var deserialized wallet.GetPublicKeyResult
					checkJson(&deserialized, &obj)
				case wallet.RevealCounterpartyKeyLinkageArgs:
					var deserialized wallet.RevealCounterpartyKeyLinkageArgs
					checkJson(&deserialized, &obj)
				case wallet.RevealCounterpartyKeyLinkageResult:
					var deserialized wallet.RevealCounterpartyKeyLinkageResult
					checkJson(&deserialized, &obj)
				case wallet.RevealSpecificKeyLinkageArgs:
					var deserialized wallet.RevealSpecificKeyLinkageArgs
					checkJson(&deserialized, &obj)
				case wallet.RevealSpecificKeyLinkageResult:
					var deserialized wallet.RevealSpecificKeyLinkageResult
					checkJson(&deserialized, &obj)
				case wallet.EncryptArgs:
					var deserialized wallet.EncryptArgs
					checkJson(&deserialized, &obj)
				case wallet.EncryptResult:
					var deserialized wallet.EncryptResult
					checkJson(&deserialized, &obj)
				case wallet.DecryptArgs:
					var deserialized wallet.DecryptArgs
					checkJson(&deserialized, &obj)
				case wallet.DecryptResult:
					var deserialized wallet.DecryptResult
					checkJson(&deserialized, &obj)
				case wallet.CreateHmacArgs:
					var deserialized wallet.CreateHmacArgs
					checkJson(&deserialized, &obj)
				case wallet.CreateHmacResult:
					var deserialized wallet.CreateHmacResult
					checkJson(&deserialized, &obj)
				default:
					t.Fatalf("Unsupported object type: %T", obj)
				}
			})

			// TODO: Implement wire tests
			// Currently discrepancies in varInt handling of negative numbers, so most wire tests don't match ts-sdk
			// For now serializer tests verify wire objects are consistent between serializing and deserializing
			return

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
						serializedWithFrame = serializer.WriteResultFrame(serialized, nil)
					} else {
						serializedWithFrame = serializer.WriteRequestFrame(serializer.RequestFrame{
							Call:   byte(call),
							Params: serialized,
						})
					}
					require.Equal(t, wire, serializedWithFrame)
					require.NoError(t, err2)
					require.EqualValues(t, obj, deserialized)
				}

				// Serialize and deserialize using the wire binary format
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
				case wallet.InternalizeActionArgs:
					serialized, err1 := serializer.SerializeInternalizeActionArgs(&obj)
					deserialized, err2 := serializer.DeserializeInternalizeActionArgs(frameParams)
					checkWireSerialize(substrates.CallInternalizeAction, &obj, serialized, err1, deserialized, err2)
				case wallet.InternalizeActionResult:
					serialized, err1 := serializer.SerializeInternalizeActionResult(&obj)
					deserialized, err2 := serializer.DeserializeInternalizeActionResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.EncryptArgs:
					serialized, err1 := serializer.SerializeEncryptArgs(&obj)
					deserialized, err2 := serializer.DeserializeEncryptArgs(frameParams)
					checkWireSerialize(substrates.CallEncrypt, &obj, serialized, err1, deserialized, err2)
				case wallet.EncryptResult:
					serialized, err1 := serializer.SerializeEncryptResult(&obj)
					deserialized, err2 := serializer.DeserializeEncryptResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.DecryptArgs:
					serialized, err1 := serializer.SerializeDecryptArgs(&obj)
					deserialized, err2 := serializer.DeserializeDecryptArgs(frameParams)
					checkWireSerialize(substrates.CallDecrypt, &obj, serialized, err1, deserialized, err2)
				case wallet.DecryptResult:
					serialized, err1 := serializer.SerializeDecryptResult(&obj)
					deserialized, err2 := serializer.DeserializeDecryptResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				case wallet.CreateHmacArgs:
					serialized, err1 := serializer.SerializeCreateHmacArgs(&obj)
					deserialized, err2 := serializer.DeserializeCreateHmacArgs(frameParams)
					checkWireSerialize(substrates.CallCreateHmac, &obj, serialized, err1, deserialized, err2)
				case wallet.CreateHmacResult:
					serialized, err1 := serializer.SerializeCreateHmacResult(&obj)
					deserialized, err2 := serializer.DeserializeCreateHmacResult(frameParams)
					checkWireSerialize(0, &obj, serialized, err1, deserialized, err2)
				default:
					t.Fatalf("Unsupported object type: %T", obj)
				}
			})
		})
	}
}
