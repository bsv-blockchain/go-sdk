package substrates_test

import (
	"encoding/json"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/serializer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				// Marshal the object to JSON
				switch obj := tt.Object.(type) {
				case wallet.AbortActionArgs:
					var deserialized wallet.AbortActionArgs
					require.NoError(t, json.Unmarshal(vectorFile["json"], &deserialized))
					assert.Equal(t, obj, deserialized)
					// TODO: Test JSON Marshalled obj matches vectorFile["json"]
				}
			})

			// Test wire format serialization
			t.Run("Wire", func(t *testing.T) {
				// Marshal the object to JSON
				switch obj := tt.Object.(type) {
				case wallet.AbortActionArgs:
					deserialized, err := serializer.DeserializeAbortActionArgs(vectorFile["wire"])
					require.NoError(t, err)
					assert.Equal(t, obj, deserialized)
					// TODO: Test serialized obj matches vectorFile["wire"]
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
