package serializer

import (
	tu "github.com/bsv-blockchain/go-sdk/v2/util/test_util"
	"github.com/bsv-blockchain/go-sdk/v2/wallet"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGetHeaderArgs(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.GetHeaderArgs
	}{
		{
			name: "height 1",
			args: &wallet.GetHeaderArgs{Height: 1},
		},
		{
			name: "height 100000",
			args: &wallet.GetHeaderArgs{Height: 100000},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeGetHeaderArgs(tt.args)
			require.NoError(t, err, "serializing GetHeaderArgs should not error")

			// Test deserialization
			got, err := DeserializeGetHeaderArgs(data)
			require.NoError(t, err, "deserializing GetHeaderArgs should not error")

			// Compare results
			require.Equal(t, tt.args, got, "deserialized args should match original args")
		})
	}
}

func TestGetHeaderResult(t *testing.T) {
	testHeader := tu.GetByteFromHexString(t, "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299")

	tests := []struct {
		name   string
		result *wallet.GetHeaderResult
	}{
		{
			name: "valid header",
			result: &wallet.GetHeaderResult{
				Header: testHeader,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			data, err := SerializeGetHeaderResult(tt.result)
			require.NoError(t, err, "serializing GetHeaderResult should not error")

			// Test deserialization
			got, err := DeserializeGetHeaderResult(data)
			require.NoError(t, err, "deserializing GetHeaderResult should not error")

			// Compare results
			require.Equal(t, tt.result, got, "deserialized result should match original result")
		})
	}
}

func TestGetHeaderResultError(t *testing.T) {
	// Test error byte handling
	data := []byte{1} // Error byte = 1
	_, err := DeserializeGetHeaderResult(data)
	require.Error(t, err, "deserializing with error byte should produce an error")
	require.Contains(t, err.Error(), "error byte indicates failure", "error message should indicate failure")
}
