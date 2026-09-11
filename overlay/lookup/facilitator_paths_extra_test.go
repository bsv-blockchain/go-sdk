package lookup

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/script"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
)

// TestParseBinaryLookupAnswerErrors covers the truncated-input error branches of
// the binary output-list decoder.
func TestParseBinaryLookupAnswerErrors(t *testing.T) {
	t.Parallel()

	txid := make([]byte, 32)

	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name:    "empty data fails reading outpoint count",
			data:    []byte{},
			wantErr: "reading outpoint count",
		},
		{
			name:    "truncated after txid fails reading output index",
			data:    append([]byte{0x01}, txid...),
			wantErr: "reading outputIndex",
		},
		{
			name:    "truncated after output index fails reading context length",
			data:    append(append([]byte{0x01}, txid...), 0x00),
			wantErr: "reading contextLen",
		},
		{
			name:    "truncated context fails reading context",
			data:    append(append([]byte{0x01}, txid...), 0x00, 0x05),
			wantErr: "reading context",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseBinaryLookupAnswer(tc.data)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// TestParseBinaryLookupAnswerTxidNotInBeef covers the branch where a referenced
// txid is not present in the trailing shared BEEF.
func TestParseBinaryLookupAnswerTxidNotInBeef(t *testing.T) {
	t.Parallel()
	beef := tu.SingleOutputBeef(t, &script.Script{})

	// One outpoint referencing an all-zero txid (not present in the BEEF),
	// output index 0, no context, followed by the shared BEEF.
	data := make([]byte, 0, 1+32+2+len(beef))
	data = append(data, 0x01)
	data = append(data, make([]byte, 32)...)
	data = append(data, 0x00, 0x00)
	data = append(data, beef...)

	_, err := parseBinaryLookupAnswer(data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found in BEEF")
}
