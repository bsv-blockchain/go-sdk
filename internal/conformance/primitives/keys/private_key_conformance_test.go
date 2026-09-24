package keys_test

import (
	"encoding/hex"
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

type privateKeyInput struct {
	WIF                    string `json:"wif"`
	PrivkeyHex             string `json:"privkey_hex"`
	RecipientPrivateKeyHex string `json:"recipient_private_key_hex"`
	SenderPublicKeyHex     string `json:"sender_public_key_hex"`
	InvoiceNumber          string `json:"invoice_number"`
}

type privateKeyExpected struct {
	PrivkeyHex           string `json:"privkey_hex"`
	PrivkeyHexRoundtrip  string `json:"privkey_hex_roundtrip"`
	PubkeyHex            string `json:"pubkey_hex"`
	DerivedPrivateKeyHex string `json:"derived_private_key_hex"`
}

func assertPrivateKeyFields(t *testing.T, id string, priv *ec.PrivateKey, expected privateKeyExpected, roundtrip string) {
	t.Helper()
	if roundtrip != "" {
		if got := priv.Hex(); got != roundtrip {
			t.Errorf("%s: hex roundtrip mismatch\ngot:  %s\nwant: %s", id, got, roundtrip)
		}
	}
	if expected.PubkeyHex != "" {
		if gotHex := hex.EncodeToString(priv.PubKey().Compressed()); gotHex != expected.PubkeyHex {
			t.Errorf("%s: pubkey mismatch\ngot:  %s\nwant: %s", id, gotHex, expected.PubkeyHex)
		}
	}
}

// TestPrivateKeyConformance covers sdk.keys.privatekey: hex/WIF round-trips
// and BRC-42 private child key derivation, against primitives/ec.PrivateKey.
func TestPrivateKeyConformance(t *testing.T) {
	file := conformance.Load(t, "sdk/keys/private-key.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in privateKeyInput
		v.DecodeInput(t, &in)
		var expected privateKeyExpected
		v.DecodeExpected(t, &expected)

		switch {
		case in.WIF != "":
			priv, err := ec.PrivateKeyFromWif(in.WIF)
			if err != nil {
				t.Fatalf("%s: PrivateKeyFromWif: %v", v.ID, err)
			}
			assertPrivateKeyFields(t, v.ID, priv, expected, expected.PrivkeyHex)
		case in.PrivkeyHex != "":
			priv, err := ec.PrivateKeyFromHex(in.PrivkeyHex)
			if err != nil {
				t.Fatalf("%s: PrivateKeyFromHex: %v", v.ID, err)
			}
			assertPrivateKeyFields(t, v.ID, priv, expected, expected.PrivkeyHexRoundtrip)
		case in.RecipientPrivateKeyHex != "":
			recip, err := ec.PrivateKeyFromHex(in.RecipientPrivateKeyHex)
			if err != nil {
				t.Fatalf("%s: PrivateKeyFromHex(recipient): %v", v.ID, err)
			}
			senderPub, err := ec.PublicKeyFromString(in.SenderPublicKeyHex)
			if err != nil {
				t.Fatalf("%s: PublicKeyFromString(sender): %v", v.ID, err)
			}
			derived, err := recip.DeriveChild(senderPub, in.InvoiceNumber)
			if err != nil {
				t.Fatalf("%s: DeriveChild: %v", v.ID, err)
			}
			if got := derived.Hex(); got != expected.DerivedPrivateKeyHex {
				t.Errorf("%s: derived private key mismatch\ngot:  %s\nwant: %s", v.ID, got, expected.DerivedPrivateKeyHex)
			}
		default:
			t.Fatalf("%s: unrecognized private-key vector shape", v.ID)
		}
	})
}
