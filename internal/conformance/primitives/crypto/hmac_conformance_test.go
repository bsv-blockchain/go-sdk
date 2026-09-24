package crypto_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
)

type hmacInput struct {
	Algorithm       string `json:"algorithm"`
	Key             string `json:"key"`
	KeyEncoding     string `json:"key_encoding"`
	Message         string `json:"message"`
	MessageEncoding string `json:"message_encoding"`
}

func TestHMACConformance(t *testing.T) {
	file := conformance.Load(t, "sdk/crypto/hmac.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in hmacInput
		v.DecodeInput(t, &in)
		var expected struct {
			HMAC string `json:"hmac"`
		}
		v.DecodeExpected(t, &expected)

		key := decodeMessage(t, in.Key, in.KeyEncoding)
		msg := decodeMessage(t, in.Message, in.MessageEncoding)

		var got []byte
		switch strings.ToLower(in.Algorithm) {
		case "hmac-sha256":
			got = crypto.Sha256HMAC(msg, key)
		case "hmac-sha512":
			got = crypto.Sha512HMAC(msg, key)
		default:
			t.Fatalf("%s: unknown HMAC algorithm %q", v.ID, in.Algorithm)
		}

		if gotHex := hex.EncodeToString(got); gotHex != expected.HMAC {
			t.Errorf("%s: hmac mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, expected.HMAC)
		}
	})
}
