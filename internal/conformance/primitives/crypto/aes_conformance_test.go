package crypto_test

import (
	"encoding/hex"
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	aesgcm "github.com/bsv-blockchain/go-sdk/primitives/aesgcm"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

type aesInput struct {
	Algorithm     string `json:"algorithm"`
	Plaintext     string `json:"plaintext"`
	Key           string `json:"key"`
	KeyEncoding   string `json:"key_encoding"`
	IV            string `json:"iv"`
	CiphertextHex string `json:"ciphertext_hex"`
}

// TestAESConformance covers sdk.crypto.aes. algorithm "aes-block" exercises
// go-sdk's raw single-block AES primitive (the TS dispatcher explicitly
// leaves this shape to the Go runner: it is not publicly exported from
// @bsv/sdk). algorithm "aes-gcm" exercises AES-GCM encryption directly, and
// "aes-gcm-symmetrickey" exercises the SymmetricKey wire format (32-byte IV
// || ciphertext || 16-byte tag).
func TestAESConformance(t *testing.T) {
	file := conformance.Load(t, "sdk/crypto/aes.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in aesInput
		v.DecodeInput(t, &in)

		switch in.Algorithm {
		case "aes-block":
			var expected struct {
				Ciphertext string `json:"ciphertext"`
			}
			v.DecodeExpected(t, &expected)

			key := mustHex(t, v.ID, "key", in.Key)
			plaintext := mustHex(t, v.ID, "plaintext", in.Plaintext)
			got, err := aesgcm.AESEncrypt(plaintext, key)
			if err != nil {
				t.Fatalf("%s: AESEncrypt: %v", v.ID, err)
			}
			if gotHex := hex.EncodeToString(got); gotHex != expected.Ciphertext {
				t.Errorf("%s: aes-block mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, expected.Ciphertext)
			}

		case "aes-gcm":
			var expected struct {
				Ciphertext        string `json:"ciphertext"`
				AuthenticationTag string `json:"authentication_tag"`
			}
			v.DecodeExpected(t, &expected)

			key := mustHex(t, v.ID, "key", in.Key)
			plaintext := mustHex(t, v.ID, "plaintext", in.Plaintext)
			iv := mustHex(t, v.ID, "iv", in.IV)

			ciphertext, tag, err := aesgcm.AESGCMEncrypt(plaintext, key, iv, nil)
			if err != nil {
				t.Fatalf("%s: AESGCMEncrypt: %v", v.ID, err)
			}
			if gotHex := hex.EncodeToString(ciphertext); gotHex != expected.Ciphertext {
				t.Errorf("%s: aes-gcm ciphertext mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, expected.Ciphertext)
			}
			if gotHex := hex.EncodeToString(tag); gotHex != expected.AuthenticationTag {
				t.Errorf("%s: aes-gcm tag mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, expected.AuthenticationTag)
			}

		case "aes-gcm-symmetrickey":
			var expected struct {
				PlaintextUTF8 string `json:"plaintext_utf8"`
			}
			v.DecodeExpected(t, &expected)

			key := mustHex(t, v.ID, "key", in.Key)
			message := mustHex(t, v.ID, "ciphertext_hex", in.CiphertextHex)

			plain, err := ec.NewSymmetricKey(key).Decrypt(message)
			if err != nil {
				t.Fatalf("%s: SymmetricKey.Decrypt: %v", v.ID, err)
			}
			if string(plain) != expected.PlaintextUTF8 {
				t.Errorf("%s: plaintext mismatch\ngot:  %q\nwant: %q", v.ID, plain, expected.PlaintextUTF8)
			}

		default:
			t.Fatalf("%s: unknown algorithm %q", v.ID, in.Algorithm)
		}
	})
}
