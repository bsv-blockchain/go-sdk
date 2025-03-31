package serializer

import (
	"encoding/hex"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDeserializeSignActionResult(t *testing.T) {
	txid := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	txidBytes, _ := hex.DecodeString(txid)
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
				w := newWriter()
				w.writeByte(1) // txid present
				w.writeBytes(txidBytes)
				w.writeByte(1) // tx present
				w.writeVarInt(uint64(len(tx)))
				w.writeBytes(tx)
				w.writeVarInt(1) // 1 sendWith result
				w.writeBytes(txidBytes)
				w.writeByte(2) // status = sending
				return w.buf
			}(),
			want: &wallet.SignActionResult{
				Txid: txid,
				Tx:   tx,
				SendWithResults: []wallet.SendWithResult{
					{Txid: txid, Status: "sending"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeserializeSignActionResult(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeserializeSignActionResult() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
