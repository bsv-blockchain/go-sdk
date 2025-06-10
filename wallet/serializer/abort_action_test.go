package serializer

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/v2/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAbortActionArgsSerializeAndDeserialize(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.AbortActionArgs
	}{
		{
			name: "full args",
			args: &wallet.AbortActionArgs{
				Reference: []byte{1, 2, 3},
			},
		},
		{
			name: "empty reference",
			args: &wallet.AbortActionArgs{
				Reference: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Serialize
			data, err := SerializeAbortActionArgs(tt.args)
			require.NoError(t, err, "serializing AbortActionArgs should not error")

			// Deserialize
			args, err := DeserializeAbortActionArgs(data)
			require.NoError(t, err, "deserializing AbortActionArgs should not error")

			// Compare
			require.Equal(t, tt.args, args, "deserialized args should match original args")
		})
	}
}

func TestAbortActionResultSerializeAndDeserialize(t *testing.T) {
	t.Run("successful abort", func(t *testing.T) {
		testResult := &wallet.AbortActionResult{
			Aborted: true,
		}

		// Serialize
		data, err := SerializeAbortActionResult(testResult)
		require.NoError(t, err, "serializing AbortActionResult should not error")
		require.Empty(t, data, "serialized data should be empty")

		// Deserialize
		result, err := DeserializeAbortActionResult(data)
		require.NoError(t, err, "deserializing AbortActionResult should not error")

		// Compare
		require.Equal(t, testResult, result, "deserialized result should match original result")
	})
}

func TestSerializeAbortActionArgs(t *testing.T) {
	tests := []struct {
		name string
		args wallet.AbortActionArgs
		want []byte
	}{
		{
			name: "valid reference",
			args: wallet.AbortActionArgs{
				Reference: []byte{1, 2, 3},
			},
			want: []byte{1, 2, 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SerializeAbortActionArgs(&tt.args)
			assert.NoError(t, err, "SerializeAbortActionArgs() error = %v", err)
			assert.Equal(t, tt.want, got, "SerializeAbortActionArgs() = %v, want %v", got, tt.want)
		})
	}
}

func TestDeserializeAbortActionArgs(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    *wallet.AbortActionArgs
		wantErr bool
	}{
		{
			name: "valid reference",
			data: []byte{1, 2, 3},
			want: &wallet.AbortActionArgs{
				Reference: []byte{1, 2, 3},
			},
		},
		{
			name: "empty data",
			want: &wallet.AbortActionArgs{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeserializeAbortActionArgs(tt.data)
			assert.NoError(t, err, "DeserializeAbortActionArgs() error = %v", err)
			assert.Equal(t, tt.want, got, "DeserializeAbortActionArgs() = %v, want %v", got, tt.want)
		})
	}
}

func TestSerializeAbortActionResult(t *testing.T) {
	result := &wallet.AbortActionResult{Aborted: true}
	data, err := SerializeAbortActionResult(result)
	assert.NoError(t, err, "SerializeAbortActionResult() error = %v", err)
	assert.Equal(t, []byte(nil), data, "SerializeAbortActionResult() = %v, want %v", data, []byte(nil))
}

func TestDeserializeAbortActionResult(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want *wallet.AbortActionResult
	}{
		{
			name: "success",
			data: []byte{},
			want: &wallet.AbortActionResult{Aborted: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeserializeAbortActionResult(tt.data)
			if err != nil {
				t.Errorf("DeserializeAbortActionResult() error = %v", err)
				return
			}
			assert.Equal(t, tt.want, got, "DeserializeAbortActionResult() = %v, want %v", got, tt.want)
		})
	}
}
