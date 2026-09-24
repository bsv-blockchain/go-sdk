package crypto_test

import (
	"encoding/hex"
	"testing"

	ecies "github.com/bsv-blockchain/go-sdk/compat/ecies"
	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

type eciesInput struct {
	SenderPrivateKey      string `json:"sender_private_key"`
	SenderPublicKey       string `json:"sender_public_key"`
	RecipientPrivateKey   string `json:"recipient_private_key"`
	RecipientPublicKey    string `json:"recipient_public_key"`
	AlicePrivateKey       string `json:"alice_private_key"`
	AlicePublicKey        string `json:"alice_public_key"`
	BobPrivateKey         string `json:"bob_private_key"`
	BobPublicKey          string `json:"bob_public_key"`
	Message               string `json:"message"`
	MessageEncoding       string `json:"message_encoding"`
	NoKey                 bool   `json:"no_key"`
	CiphertextHex         string `json:"ciphertext_hex"`
	TamperedCiphertextHex string `json:"tampered_ciphertext_hex"`
}

func eciesMessageBytes(t *testing.T, id string, in eciesInput) []byte {
	t.Helper()
	if in.MessageEncoding == "hex" {
		return hexOrEmpty(t, id, "message", in.Message)
	}
	return []byte(in.Message)
}

// TestECIESConformance covers sdk.crypto.ecies (the Electrum ECIES variant),
// against compat/ecies's ElectrumEncrypt/ElectrumDecrypt.
func TestECIESConformance(t *testing.T) {
	file := conformance.Load(t, "sdk/crypto/ecies.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in eciesInput
		v.DecodeInput(t, &in)
		var expected struct {
			CiphertextHex            string `json:"ciphertext_hex"`
			DecryptedMessage         string `json:"decrypted_message"`
			DecryptedMessageUTF8     string `json:"decrypted_message_utf8"`
			DecryptedMessageLenBytes *int   `json:"decrypted_message_length_bytes"`
			CiphertextSymmetric      bool   `json:"ciphertext_symmetric"`
			Throws                   bool   `json:"throws"`
			RoundtripOnly            bool   `json:"_roundtrip_only"`
		}
		v.DecodeExpected(t, &expected)

		switch {
		case in.NoKey:
			eciesNoKeyMode(t, v, in, expected.CiphertextSymmetric, expected.DecryptedMessageUTF8)
		case in.TamperedCiphertextHex != "":
			eciesTampered(t, v, in, expected.Throws)
		case in.SenderPrivateKey == "" && in.CiphertextHex != "" && in.RecipientPrivateKey != "":
			eciesDecryptOnly(t, v, in, expected.DecryptedMessage)
		case in.SenderPrivateKey != "":
			eciesFullRoundtrip(t, v, in, expected.CiphertextHex, expected.DecryptedMessage, expected.DecryptedMessageLenBytes)
		case expected.RoundtripOnly:
			// sdk.crypto.ecies.22: ciphertext is non-deterministic (no
			// fixed sender key given for this shape); decrypt must still
			// recover the original message. Not reached by the current
			// corpus (vector 22 supplies sender_private_key), but handled
			// defensively should that shape appear.
			t.Fatalf("%s: roundtrip-only vector with no sender_private_key is not supported by this test", v.ID)
		default:
			t.Fatalf("%s: unrecognized ecies vector shape", v.ID)
		}
	})
}

func eciesNoKeyMode(t *testing.T, v conformance.Vector, in eciesInput, wantSymmetric bool, wantPlainUTF8 string) {
	t.Helper()
	alicePriv, err := ec.PrivateKeyFromHex(in.AlicePrivateKey)
	if err != nil {
		t.Fatalf("%s: alice priv: %v", v.ID, err)
	}
	alicePub, err := ec.PublicKeyFromString(in.AlicePublicKey)
	if err != nil {
		t.Fatalf("%s: alice pub: %v", v.ID, err)
	}
	bobPriv, err := ec.PrivateKeyFromHex(in.BobPrivateKey)
	if err != nil {
		t.Fatalf("%s: bob priv: %v", v.ID, err)
	}
	bobPub, err := ec.PublicKeyFromString(in.BobPublicKey)
	if err != nil {
		t.Fatalf("%s: bob pub: %v", v.ID, err)
	}
	msg := eciesMessageBytes(t, v.ID, in)

	ct1, err := ecies.ElectrumEncrypt(msg, bobPub, alicePriv, true)
	if err != nil {
		t.Fatalf("%s: ElectrumEncrypt(alice->bob): %v", v.ID, err)
	}
	ct2, err := ecies.ElectrumEncrypt(msg, alicePub, bobPriv, true)
	if err != nil {
		t.Fatalf("%s: ElectrumEncrypt(bob->alice): %v", v.ID, err)
	}
	if wantSymmetric && hex.EncodeToString(ct1) != hex.EncodeToString(ct2) {
		t.Errorf("%s: no_key ciphertexts differ, want symmetric", v.ID)
	}
	if wantPlainUTF8 != "" {
		plain, err := ecies.ElectrumDecrypt(ct1, bobPriv, alicePub)
		if err != nil {
			t.Fatalf("%s: ElectrumDecrypt: %v", v.ID, err)
		}
		if string(plain) != wantPlainUTF8 {
			t.Errorf("%s: decrypted = %q, want %q", v.ID, plain, wantPlainUTF8)
		}
	}
}

func eciesTampered(t *testing.T, v conformance.Vector, in eciesInput, wantThrows bool) {
	t.Helper()
	tampered := hexOrEmpty(t, v.ID, "tampered_ciphertext_hex", in.TamperedCiphertextHex)
	recipPriv, err := ec.PrivateKeyFromHex(in.RecipientPrivateKey)
	if err != nil {
		t.Fatalf("%s: recipient priv: %v", v.ID, err)
	}
	senderPub, err := ec.PublicKeyFromString(in.SenderPublicKey)
	if err != nil {
		t.Fatalf("%s: sender pub: %v", v.ID, err)
	}
	_, err = ecies.ElectrumDecrypt(tampered, recipPriv, senderPub)
	if wantThrows && err == nil {
		t.Errorf("%s: decrypting tampered ciphertext did not error", v.ID)
	}
}

func eciesDecryptOnly(t *testing.T, v conformance.Vector, in eciesInput, wantDecryptedHex string) {
	t.Helper()
	ct := hexOrEmpty(t, v.ID, "ciphertext_hex", in.CiphertextHex)
	recipPriv, err := ec.PrivateKeyFromHex(in.RecipientPrivateKey)
	if err != nil {
		t.Fatalf("%s: recipient priv: %v", v.ID, err)
	}
	plain, err := ecies.ElectrumDecrypt(ct, recipPriv, nil)
	if err != nil {
		t.Fatalf("%s: ElectrumDecrypt: %v", v.ID, err)
	}
	if gotHex := hex.EncodeToString(plain); gotHex != wantDecryptedHex {
		t.Errorf("%s: decrypted = %s, want %s", v.ID, gotHex, wantDecryptedHex)
	}
}

func eciesFullRoundtrip(t *testing.T, v conformance.Vector, in eciesInput, wantCiphertextHex, wantDecryptedHex string, wantDecryptedLen *int) {
	t.Helper()
	senderPriv, err := ec.PrivateKeyFromHex(in.SenderPrivateKey)
	if err != nil {
		t.Fatalf("%s: sender priv: %v", v.ID, err)
	}
	recipPub, err := ec.PublicKeyFromString(in.RecipientPublicKey)
	if err != nil {
		t.Fatalf("%s: recipient pub: %v", v.ID, err)
	}
	msg := eciesMessageBytes(t, v.ID, in)

	ct, err := ecies.ElectrumEncrypt(msg, recipPub, senderPriv, false)
	if err != nil {
		t.Fatalf("%s: ElectrumEncrypt: %v", v.ID, err)
	}
	if wantCiphertextHex != "" {
		if gotHex := hex.EncodeToString(ct); gotHex != wantCiphertextHex {
			t.Errorf("%s: ciphertext mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, wantCiphertextHex)
		}
	}

	if in.RecipientPrivateKey == "" {
		return
	}
	recipPriv, err := ec.PrivateKeyFromHex(in.RecipientPrivateKey)
	if err != nil {
		t.Fatalf("%s: recipient priv: %v", v.ID, err)
	}
	plain, err := ecies.ElectrumDecrypt(ct, recipPriv, senderPriv.PubKey())
	if err != nil {
		t.Fatalf("%s: ElectrumDecrypt: %v", v.ID, err)
	}
	if wantDecryptedHex != "" {
		if gotHex := hex.EncodeToString(plain); gotHex != wantDecryptedHex {
			t.Errorf("%s: decrypted mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, wantDecryptedHex)
		}
	} else if wantDecryptedLen != nil {
		if len(plain) != *wantDecryptedLen {
			t.Errorf("%s: decrypted length = %d, want %d", v.ID, len(plain), *wantDecryptedLen)
		}
	} else if len(msg) > 0 {
		// sdk.crypto.ecies.22 (all-zero roundtrip): no fixed hex/length
		// expectation is given, so assert the roundtrip property directly.
		if hex.EncodeToString(plain) != hex.EncodeToString(msg) {
			t.Errorf("%s: roundtrip mismatch: decrypted plaintext does not match original message", v.ID)
		}
	}
}
