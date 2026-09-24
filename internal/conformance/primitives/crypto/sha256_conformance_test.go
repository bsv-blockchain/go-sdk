package crypto_test

import (
	"encoding/hex"
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
)

// sha256Input mirrors the sdk.crypto.sha256 vector shape (also reused by
// ripemd160.json, which has the same input/expected shape).
type sha256Input struct {
	Message  string `json:"message"`
	Encoding string `json:"encoding"`
	Double   bool   `json:"double"`
}

func TestSHA256Conformance(t *testing.T) {
	file := conformance.Load(t, "sdk/crypto/sha256.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in sha256Input
		v.DecodeInput(t, &in)
		var expected struct {
			Hash string `json:"hash"`
		}
		v.DecodeExpected(t, &expected)

		data := decodeMessage(t, in.Message, in.Encoding)
		var got []byte
		if in.Double {
			got = crypto.Sha256d(data)
		} else {
			got = crypto.Sha256(data)
		}
		if gotHex := hex.EncodeToString(got); gotHex != expected.Hash {
			t.Errorf("%s: sha256 mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, expected.Hash)
		}
	})
}
