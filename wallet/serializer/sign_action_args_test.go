package serializer

import (
	"encoding/base64"
	"github.com/bsv-blockchain/go-sdk/wallet"
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
				},
				Reference: base64.StdEncoding.EncodeToString([]byte("ref123")),
				Options: &wallet.SignActionOptions{
					AcceptDelayedBroadcast: boolPtr(true),
					SendWith:               []string{"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SerializeSignActionArgs(&tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("SerializeSignActionArgs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) == 0 {
				t.Error("SerializeSignActionArgs() returned empty bytes")
			}
		})
	}
}
