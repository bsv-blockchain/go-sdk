package serializer

import (
	"encoding/base64"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAbortActionArgsSerializeAndDeserialize(t *testing.T) {
	tests := []struct {
		name string
		args *wallet.AbortActionArgs
	}{
		{
			name: "full args",
			args: &wallet.AbortActionArgs{
				Reference: base64.StdEncoding.EncodeToString([]byte("test-reference-123")),
			},
		},
		{
			name: "empty reference",
			args: &wallet.AbortActionArgs{
				Reference: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Serialize
			data, err := SerializeAbortActionArgs(tt.args)
			require.NoError(t, err)
			require.NotEmpty(t, data)

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
		name string
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
			require.NotEmpty(t, data)

			// Deserialize
			result, err := DeserializeAbortActionResult(data)
			require.NoError(t, err)

			// Compare
			require.Equal(t, tt.result, result)
		})
	}

	// Test error case
	t.Run("error response", func(t *testing.T) {
		// Create error response data
		w := newWriter()
		w.writeByte(1) // error code
		w.writeString("abort failed")
		w.writeString("stack trace")

		_, err := DeserializeAbortActionResult(w.buf)
		require.Error(t, err)
		require.Contains(t, err.Error(), "abort failed")
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
				Reference: base64.StdEncoding.EncodeToString([]byte("test-ref")),
			},
			want:    append([]byte{0x08}, []byte("test-ref")...),
			wantErr: false,
		},
		{
			name: "invalid base64 reference",
			args: wallet.AbortActionArgs{
				Reference: "invalid",
			},
			wantErr: true,
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
			data: append([]byte{0x08}, []byte("test-ref")...),
			want: &wallet.AbortActionArgs{
				Reference: base64.StdEncoding.EncodeToString([]byte("test-ref")),
			},
			wantErr: false,
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeserializeAbortActionArgs(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeserializeAbortActionArgs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestSerializeAbortActionResult(t *testing.T) {
	result := &wallet.AbortActionResult{Aborted: true}
	data, err := SerializeAbortActionResult(result)
	assert.NoError(t, err)
	assert.Equal(t, []byte{0}, data) // Success byte
}

func TestDeserializeAbortActionResult(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    *wallet.AbortActionResult
		wantErr bool
	}{
		{
			name:    "success",
			data:    []byte{0},
			want:    &wallet.AbortActionResult{Aborted: true},
			wantErr: false,
		},
		{
			name:    "error",
			data:    []byte{1, 0x0b, 'e', 'r', 'r', 'o', 'r', ' ', 'm', 's', 'g'},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeserializeAbortActionResult(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeserializeAbortActionResult() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
