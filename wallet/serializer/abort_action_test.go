package serializer

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/wallet"
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
			require.NoError(t, err)

			// Deserialize
			args, err := DeserializeAbortActionArgs(data)
			require.NoError(t, err)

			// Compare
			require.Equal(t, tt.args, args)
		})
	}
}

func TestAbortActionResultSerializeAndDeserialize(t *testing.T) {
	tests := []struct {
		name   string
		result *wallet.AbortActionResult
	}{
		{
			name: "successful abort",
			result: &wallet.AbortActionResult{
				Aborted: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Serialize
			data, err := SerializeAbortActionResult(tt.result)
			require.NoError(t, err)
			require.Empty(t, data) // Abort action result has no additional data

			// Deserialize
			result, err := DeserializeAbortActionResult(data)
			require.NoError(t, err)

			// Compare
			require.Equal(t, tt.result, result)
		})
	}

	// Test error case
	t.Run("error response", func(t *testing.T) {
		result, err := DeserializeAbortActionResult([]byte{})
		require.NoError(t, err)
		require.Equal(t, result.Aborted, true)
	})
}

func TestSerializeAbortActionArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    wallet.AbortActionArgs
		want    []byte
		wantErr bool
	}{
		{
			name: "valid reference",
			args: wallet.AbortActionArgs{
				Reference: []byte{1, 2, 3},
			},
			want:    []byte{1, 2, 3},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SerializeAbortActionArgs(&tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("SerializeAbortActionArgs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				assert.Equal(t, tt.want, got)
			}
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
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSerializeAbortActionResult(t *testing.T) {
	result := &wallet.AbortActionResult{Aborted: true}
	data, err := SerializeAbortActionResult(result)
	assert.NoError(t, err)
	assert.Equal(t, []byte(nil), data) // No additional data
}

func TestDeserializeAbortActionResult(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    *wallet.AbortActionResult
	}{
		{
			name:    "success",
			data:    []byte{},
			want:    &wallet.AbortActionResult{Aborted: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeserializeAbortActionResult(tt.data)
			if err != nil {
				t.Errorf("DeserializeAbortActionResult() error = %v", err)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
