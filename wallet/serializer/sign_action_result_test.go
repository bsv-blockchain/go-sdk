package serializer

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"testing"
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
					{Txid: txid, Status: "sending"},
					{Txid: txid, Status: "failed"},
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
			if (err != nil) != tt.wantErr {
				t.Errorf("SerializeSignActionResult() error = %v, wantErr %v", err, tt.wantErr)
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
				w := newWriter()
				w.writeByte(1) // txid present
				w.writeBytes(txidBytes)
				w.writeByte(1) // tx present
				w.writeVarInt(uint64(len(tx)))
				w.writeBytes(tx)
				w.writeVarInt(2) // 2 sendWith results
				w.writeBytes(txidBytes)
				w.writeByte(2) // status = sending
				w.writeBytes(txidBytes)
				w.writeByte(3) // status = failed
				return w.buf
			}(),
			want: &wallet.SignActionResult{
				Txid: txid,
				Tx:   tx,
				SendWithResults: []wallet.SendWithResult{
					{Txid: txid, Status: "sending"},
					{Txid: txid, Status: "failed"},
				},
			},
			wantErr: false,
		},
		{
			name: "only txid",
			data: func() []byte {
				w := newWriter()
				w.writeByte(1) // txid present
				w.writeBytes(txidBytes)
				w.writeByte(0)   // tx not present
				w.writeVarInt(0) // no sendWith results
				return w.buf
			}(),
			want: &wallet.SignActionResult{
				Txid: txid,
			},
			wantErr: false,
		},
		{
			name: "invalid status byte",
			data: func() []byte {
				w := newWriter()
				w.writeVarInt(1) // 1 sendWith result
				w.writeBytes(txidBytes)
				w.writeByte(4) // invalid status
				return w.buf
			}(),
			wantErr: true,
		},
		{
			name: "invalid txid length",
			data: func() []byte {
				w := newWriter()
				w.writeByte(1)                // txid present
				w.writeBytes([]byte{1, 2, 3}) // invalid length
				return w.buf
			}(),
			wantErr: true,
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
