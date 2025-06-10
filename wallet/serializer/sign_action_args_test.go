package serializer

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/util"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

func TestSerializeSignActionArgs(t *testing.T) {
	tests := []struct {
		name string
		args wallet.SignActionArgs
	}{
		{
			name: "basic args",
			args: wallet.SignActionArgs{
				Spends: map[uint32]wallet.SignActionSpend{
					0: {
						UnlockingScript: []byte{0xab, 0xcd, 0xef},
						SequenceNumber:  123,
					},
					1: {
						UnlockingScript: []byte{0xde, 0xad, 0xbe, 0xef},
						SequenceNumber:  456,
					},
				},
				Reference: []byte("ref123"),
				Options: &wallet.SignActionOptions{
					AcceptDelayedBroadcast: util.BoolPtr(true),
					ReturnTXIDOnly:         util.BoolPtr(false),
					NoSend:                 util.BoolPtr(true),
					SendWith: []chainhash.Hash{
						tu.HashFromString(t, "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
						tu.HashFromString(t, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
					},
				},
			},
		},
		{
			name: "minimal args",
			args: wallet.SignActionArgs{
				Spends: map[uint32]wallet.SignActionSpend{
					0: {
						UnlockingScript: []byte{0x00},
						SequenceNumber:  0,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SerializeSignActionArgs(&tt.args)
			require.NoError(t, err, "expected no error but got %v", err)
		})
	}
}

func TestDeserializeSignActionArgs(t *testing.T) {
	txid, err := chainhash.NewHashFromHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	require.NoError(t, err, "failed to create txid from hex: %v", err)
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
				w := util.NewWriter()
				w.WriteVarInt(2) // 2 spends

				// Spend 0
				w.WriteVarInt(0)
				w.WriteVarInt(uint64(len(script)))
				w.WriteBytes(script)
				w.WriteVarInt(123)

				// Spend 1
				w.WriteVarInt(1)
				w.WriteVarInt(uint64(len(script)))
				w.WriteBytes(script)
				w.WriteVarInt(456)

				// Reference
				w.WriteVarInt(uint64(len(ref)))
				w.WriteBytes(ref)

				// Options
				w.WriteByte(1)   // present
				w.WriteByte(1)   // acceptDelayedBroadcast = true
				w.WriteByte(0)   // returnTXIDOnly = false
				w.WriteByte(1)   // noSend = true
				w.WriteVarInt(2) // 2 sendWith
				w.WriteBytes(txid[:])
				w.WriteBytes(txid[:])
				return w.Buf
			}(),
			want: &wallet.SignActionArgs{
				Spends: map[uint32]wallet.SignActionSpend{
					0: {
						UnlockingScript: script,
						SequenceNumber:  123,
					},
					1: {
						UnlockingScript: script,
						SequenceNumber:  456,
					},
				},
				Reference: ref,
				Options: &wallet.SignActionOptions{
					AcceptDelayedBroadcast: util.BoolPtr(true),
					ReturnTXIDOnly:         util.BoolPtr(false),
					NoSend:                 util.BoolPtr(true),
					SendWith:               []chainhash.Hash{*txid, *txid},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid spend count",
			data: func() []byte {
				w := util.NewWriter()
				w.WriteVarInt(1 << 32) // invalid count
				return w.Buf
			}(),
			wantErr: true,
		},
		{
			name: "invalid txid length",
			data: func() []byte {
				w := util.NewWriter()
				w.WriteVarInt(1) // 1 spend
				w.WriteVarInt(0) // index 0
				w.WriteVarInt(3) // script length
				w.WriteBytes([]byte{1, 2, 3})
				w.WriteVarInt(0) // sequence
				w.WriteVarInt(3) // ref length
				w.WriteBytes([]byte{1, 2, 3})
				w.WriteByte(1)                // options present
				w.WriteVarInt(1)              // 1 sendWith
				w.WriteBytes([]byte{1, 2, 3}) // invalid txid
				return w.Buf
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeserializeSignActionArgs(tt.data)
			if tt.wantErr {
				require.Error(t, err, "expected error but got nil")
			} else {
				require.NoError(t, err, "expected no error but got %v", err)
				require.Equal(t, tt.want, got, "expected %v but got %v", tt.want, got)
			}
		})
	}
}
