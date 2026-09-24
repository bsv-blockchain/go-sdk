package crypto_test

import (
	"encoding/hex"
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
)

func TestRIPEMD160Conformance(t *testing.T) {
	file := conformance.Load(t, "sdk/crypto/ripemd160.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in sha256Input // same {message, encoding} shape
		v.DecodeInput(t, &in)
		var expected struct {
			Hash string `json:"hash"`
		}
		v.DecodeExpected(t, &expected)

		data := decodeMessage(t, in.Message, in.Encoding)
		got := crypto.Ripemd160(data)
		if gotHex := hex.EncodeToString(got); gotHex != expected.Hash {
			t.Errorf("%s: ripemd160 mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, expected.Hash)
		}
	})
}
