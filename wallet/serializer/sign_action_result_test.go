package serializer

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestSerializeSignActionResult(t *testing.T) {
	txid := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	tx := []byte{1, 2, 3, 4, 5}

	tests := []struct {
		name    string
		input   *wallet.SignActionResult
		wantErr bool
	}{
		{
			name: "full result",
			input: &wallet.SignActionResult{
				Txid: txid,
				Tx:   tx,
				SendWithResults: []wallet.SendWithResult{
					{Txid: txid, Status: wallet.ActionResultStatusSending},
					{Txid: txid, Status: wallet.ActionResultStatusFailed},
				},
			},
			wantErr: false,
		},
		{
			name: "only txid",
			input: &wallet.SignActionResult{
				Txid: txid,
			},
			wantErr: false,
		},
		{
			name: "only tx",
			input: &wallet.SignActionResult{
				Tx: tx,
			},
			wantErr: false,
		},
		{
			name: "invalid txid hex",
			input: &wallet.SignActionResult{
				Txid: "invalid",
			},
			wantErr: true,
		},
		{
			name: "invalid status",
			input: &wallet.SignActionResult{
				SendWithResults: []wallet.SendWithResult{
					{Status: "invalid"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SerializeSignActionResult(tt.input)
			if tt.wantErr {
				require.Error(t, err, "expected error but got nil")
			} else {
				require.NoError(t, err, "expected no error but got %v", err)
			}
		})
	}
}

func TestDeserializeSignActionResult(t *testing.T) {
	txid := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	txidBytes := fromHex(t, txid)
	tx := []byte{1, 2, 3, 4, 5}

	tests := []struct {
		name    string
		data    []byte
		want    *wallet.SignActionResult
		wantErr bool
	}{
		{
			name: "full result",
			data: func() []byte {
				w := util.NewWriter()
				w.WriteByte(1) // txid present
				w.WriteBytes(txidBytes)
				w.WriteByte(1) // tx present
				w.WriteVarInt(uint64(len(tx)))
				w.WriteBytes(tx)
				w.WriteVarInt(2) // 2 sendWith results
				w.WriteBytes(txidBytes)
				w.WriteByte(2) // status = sending
				w.WriteBytes(txidBytes)
				w.WriteByte(3) // status = failed
				return w.Buf
			}(),
			want: &wallet.SignActionResult{
				Txid: txid,
				Tx:   tx,
				SendWithResults: []wallet.SendWithResult{
					{Txid: txid, Status: wallet.ActionResultStatusSending},
					{Txid: txid, Status: wallet.ActionResultStatusFailed},
				},
			},
			wantErr: false,
		},
		{
			name: "only txid",
			data: func() []byte {
				w := util.NewWriter()
				w.WriteByte(1) // txid present
				w.WriteBytes(txidBytes)
				w.WriteByte(0)   // tx not present
				w.WriteVarInt(0) // no sendWith results
				return w.Buf
			}(),
			want: &wallet.SignActionResult{
				Txid: txid,
			},
			wantErr: false,
		},
		{
			name: "invalid status byte",
			data: func() []byte {
				w := util.NewWriter()
				w.WriteVarInt(1) // 1 sendWith result
				w.WriteBytes(txidBytes)
				w.WriteByte(4) // invalid status
				return w.Buf
			}(),
			wantErr: true,
		},
		{
			name: "invalid txid length",
			data: func() []byte {
				w := util.NewWriter()
				w.WriteByte(1)                // txid present
				w.WriteBytes([]byte{1, 2, 3}) // invalid length
				return w.Buf
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeserializeSignActionResult(tt.data)
			if tt.wantErr {
				require.Error(t, err, "expected error but got nil")
				return
			}
			require.NoError(t, err, "expected no error but got %v", err)
			require.Equal(t, tt.want, got, "expected %v but got %v", tt.want, got)
		})
	}
}
