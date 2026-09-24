package crypto_test

import (
	"encoding/hex"
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
)

// hash160Input mirrors sdk.crypto.hash160: either a "pubkey" hex string, or
// a generic "message"/"encoding" pair (the TS dispatcher hashes the pubkey
// bytes when pubkey is non-empty, otherwise the decoded message).
type hash160Input struct {
	Pubkey   string `json:"pubkey"`
	Message  string `json:"message"`
	Encoding string `json:"encoding"`
}

func TestHash160Conformance(t *testing.T) {
	file := conformance.Load(t, "sdk/crypto/hash160.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in hash160Input
		v.DecodeInput(t, &in)
		var expected struct {
			Hash160 string `json:"hash160"`
		}
		v.DecodeExpected(t, &expected)

		var data []byte
		if in.Pubkey != "" {
			var err error
			data, err = hex.DecodeString(in.Pubkey)
			if err != nil {
				t.Fatalf("%s: decode pubkey: %v", v.ID, err)
			}
		} else {
			data = decodeMessage(t, in.Message, in.Encoding)
		}

		got := crypto.Hash160(data)
		if gotHex := hex.EncodeToString(got); gotHex != expected.Hash160 {
			t.Errorf("%s: hash160 mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, expected.Hash160)
		}
	})
}
