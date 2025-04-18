package substrates_test

import (
	"encoding/json"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/serializer"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
)

type VectorTest struct {
	Filename string
	Object   any
}

func TestVectors(t *testing.T) {
	for _, tt := range vectorTests {
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

			// Test JSON marshaling
			t.Run("JSON", func(t *testing.T) {
				// Define a function to check JSON serialization and deserialization
				checkJson := func(emptyObj, expectedObj any) {
					assert.NoError(t, json.Unmarshal(vectorFile["json"], emptyObj))
					assert.Equal(t, expectedObj, emptyObj)
					marshaled, err := json.MarshalIndent(expectedObj, "  ", "  ")
					assert.NoError(t, err)
					assert.Equal(t, string(vectorFile["json"]), string(marshaled))
				}

				// Marshal the object to JSON
				switch obj := tt.Object.(type) {
				case wallet.AbortActionArgs:
					var deserialized wallet.AbortActionArgs
					checkJson(&deserialized, &obj)
				}
			})

			// Test wire format serialization
			t.Run("Wire", func(t *testing.T) {
				// Define a function to check wire serialization and deserialization
				checkWireSerialize := func(obj, deserialized any, err1 error, serialized any, err2 error) {
					assert.NoError(t, err1)
					assert.Equal(t, obj, deserialized)
					assert.NoError(t, err2)
					assert.Equal(t, []byte(vectorFile["wire"]), serialized)
				}

				// Marshal the object to JSON
				switch obj := tt.Object.(type) {
				case wallet.AbortActionArgs:
					deserialized, err1 := serializer.DeserializeAbortActionArgs(vectorFile["wire"])
					serialized, err2 := serializer.SerializeAbortActionArgs(&obj)
					checkWireSerialize(&obj, deserialized, err1, serialized, err2)
				}
			})
		})
	}
}

// TODO: Add the rest of the test vector files
var vectorTests = []VectorTest{{
	Filename: "abortAction-simple-args.json",
	Object: wallet.AbortActionArgs{
		Reference: "dGVzdA==",
	},
}}
