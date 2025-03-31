package serializer

import (
	"encoding/base64"
	"encoding/hex"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSerializeSignActionArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    wallet.SignActionArgs
		wantErr bool
	}{
		{
			name: "basic args",
			args: wallet.SignActionArgs{
				Spends: map[uint32]wallet.SignActionSpend{
					0: {
						UnlockingScript: "abcdef",
						SequenceNumber:  123,
					},
					1: {
						UnlockingScript: "deadbeef",
						SequenceNumber:  456,
					},
				},
				Reference: base64.StdEncoding.EncodeToString([]byte("ref123")),
				Options: &wallet.SignActionOptions{
					AcceptDelayedBroadcast: boolPtr(true),
					ReturnTXIDOnly:         boolPtr(false),
					NoSend:                 boolPtr(true),
					SendWith: []string{
						"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
						"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "minimal args",
			args: wallet.SignActionArgs{
				Spends: map[uint32]wallet.SignActionSpend{
					0: {
						UnlockingScript: "00",
						SequenceNumber:  0,
					},
				},
				Reference: base64.StdEncoding.EncodeToString([]byte("")),
			},
			wantErr: false,
		},
		{
			name: "invalid hex script",
			args: wallet.SignActionArgs{
				Spends: map[uint32]wallet.SignActionSpend{
					0: {
						UnlockingScript: "invalid",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid base64 reference",
			args: wallet.SignActionArgs{
				Reference: "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SerializeSignActionArgs(&tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("SerializeSignActionArgs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDeserializeSignActionArgs(t *testing.T) {
	txid := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	txidBytes, _ := hex.DecodeString(txid)
	script := []byte{0xab, 0xcd, 0xef}
	ref := []byte("reference123")

	tests := []struct {
		name    string
		data    []byte
		want    *wallet.SignActionArgs
		wantErr bool
	}{
		{
			name: "full args",
			data: func() []byte {
				w := newWriter()
				w.writeVarInt(2) // 2 spends

				// Spend 0
				w.writeVarInt(0)
				w.writeVarInt(uint64(len(script)))
				w.writeBytes(script)
				w.writeVarInt(123)

				// Spend 1
				w.writeVarInt(1)
				w.writeVarInt(uint64(len(script)))
				w.writeBytes(script)
				w.writeVarInt(456)

				// Reference
				w.writeVarInt(uint64(len(ref)))
				w.writeBytes(ref)

				// Options
				w.writeByte(1)   // present
				w.writeByte(1)   // acceptDelayedBroadcast = true
				w.writeByte(0)   // returnTXIDOnly = false
				w.writeByte(1)   // noSend = true
				w.writeVarInt(2) // 2 sendWith
				w.writeBytes(txidBytes)
				w.writeBytes(txidBytes)
				return w.buf
			}(),
			want: &wallet.SignActionArgs{
				Spends: map[uint32]wallet.SignActionSpend{
					0: {
						UnlockingScript: hex.EncodeToString(script),
						SequenceNumber:  123,
					},
					1: {
						UnlockingScript: hex.EncodeToString(script),
						SequenceNumber:  456,
					},
				},
				Reference: base64.StdEncoding.EncodeToString(ref),
				Options: &wallet.SignActionOptions{
					AcceptDelayedBroadcast: boolPtr(true),
					ReturnTXIDOnly:         boolPtr(false),
					NoSend:                 boolPtr(true),
					SendWith:               []string{txid, txid},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid spend count",
			data: func() []byte {
				w := newWriter()
				w.writeVarInt(1 << 32) // invalid count
				return w.buf
			}(),
			wantErr: true,
		},
		{
			name: "invalid txid length",
			data: func() []byte {
				w := newWriter()
				w.writeVarInt(1) // 1 spend
				w.writeVarInt(0) // index 0
				w.writeVarInt(3) // script length
				w.writeBytes([]byte{1, 2, 3})
				w.writeVarInt(0) // sequence
				w.writeVarInt(3) // ref length
				w.writeBytes([]byte{1, 2, 3})
				w.writeByte(1)                // options present
				w.writeVarInt(1)              // 1 sendWith
				w.writeBytes([]byte{1, 2, 3}) // invalid txid
				return w.buf
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeserializeSignActionArgs(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeserializeSignActionArgs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
