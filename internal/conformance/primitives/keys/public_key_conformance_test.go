package keys_test

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

type publicKeyInput struct {
	PrivkeyHex            string   `json:"privkey_hex"`
	PubkeyDERHex          string   `json:"pubkey_der_hex"`
	ConstructorArg        string   `json:"constructor_arg"`
	PubkeyX               *float64 `json:"pubkey_x"`
	PubkeyY               *float64 `json:"pubkey_y"`
	SenderPrivateKeyHex   string   `json:"sender_private_key_hex"`
	RecipientPublicKeyHex string   `json:"recipient_public_key_hex"`
	InvoiceNumber         string   `json:"invoice_number"`
}

type publicKeyExpected struct {
	PubkeyDERHex          string `json:"pubkey_der_hex"`
	DERLengthBytes        *int   `json:"der_length_bytes"`
	DERHexLengthChars     *int   `json:"der_hex_length_chars"`
	PubkeyDERHexRoundtrip string `json:"pubkey_der_hex_roundtrip"`
	Throws                bool   `json:"throws"`
	DerivedPublicKeyHex   string `json:"derived_public_key_hex"`
}

// TestPublicKeyConformance covers sdk.keys.publickey: DER encoding,
// fromString round-trips, BRC-42 public child derivation, and the
// ECDH-on-invalid-point error path, against primitives/ec.PublicKey.
//
// pubkey-constructor-err-001 is a GoGap: the TS dispatcher itself skips
// `constructor_arg` vectors without asserting (`dispatchPublicKey` returns
// early when the field is present), because it exercises a TS-only
// ambiguity — `new PublicKey(derHexString)` — that go-sdk's PublicKey type
// has no equivalent for (its fields are set directly; there is no
// constructor overload to confuse with fromString).
func TestPublicKeyConformance(t *testing.T) {
	file := conformance.Load(t, "sdk/keys/public-key.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in publicKeyInput
		v.DecodeInput(t, &in)
		var expected publicKeyExpected
		v.DecodeExpected(t, &expected)

		switch {
		case in.ConstructorArg != "":
			conformance.GoGap(t, "TS dispatcher skips constructor_arg shapes without asserting; go-sdk's PublicKey has no ambiguous DER-string constructor to exercise")
		case in.PrivkeyHex != "":
			pubkeyFromPrivkey(t, v, in, expected)
		case in.PubkeyDERHex != "":
			pubkeyRoundtrip(t, v, in, expected)
		case in.PubkeyX != nil:
			pubkeyECDHError(t, v, in, expected)
		case in.SenderPrivateKeyHex != "":
			pubkeyBRC42(t, v, in, expected)
		default:
			t.Fatalf("%s: unrecognized public-key vector shape", v.ID)
		}
	})
}

func pubkeyFromPrivkey(t *testing.T, v conformance.Vector, in publicKeyInput, expected publicKeyExpected) {
	t.Helper()
	priv, err := ec.PrivateKeyFromHex(in.PrivkeyHex)
	if err != nil {
		t.Fatalf("%s: PrivateKeyFromHex: %v", v.ID, err)
	}
	der := priv.PubKey().Compressed()
	if expected.PubkeyDERHex != "" {
		if gotHex := hex.EncodeToString(der); gotHex != expected.PubkeyDERHex {
			t.Errorf("%s: der mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, expected.PubkeyDERHex)
		}
	}
	if expected.DERLengthBytes != nil && len(der) != *expected.DERLengthBytes {
		t.Errorf("%s: der length = %d bytes, want %d", v.ID, len(der), *expected.DERLengthBytes)
	}
	if expected.DERHexLengthChars != nil {
		if got := len(hex.EncodeToString(der)); got != *expected.DERHexLengthChars {
			t.Errorf("%s: der hex length = %d chars, want %d", v.ID, got, *expected.DERHexLengthChars)
		}
	}
}

func pubkeyRoundtrip(t *testing.T, v conformance.Vector, in publicKeyInput, expected publicKeyExpected) {
	t.Helper()
	pub, err := ec.PublicKeyFromString(in.PubkeyDERHex)
	if err != nil {
		t.Fatalf("%s: PublicKeyFromString: %v", v.ID, err)
	}
	want := expected.PubkeyDERHexRoundtrip
	if want == "" {
		want = expected.PubkeyDERHex
	}
	if want == "" {
		return
	}
	if gotHex := hex.EncodeToString(pub.Compressed()); gotHex != want {
		t.Errorf("%s: roundtrip mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, want)
	}
}

func pubkeyECDHError(t *testing.T, v conformance.Vector, in publicKeyInput, expected publicKeyExpected) {
	t.Helper()
	x := new(big.Int).SetInt64(int64(*in.PubkeyX))
	y := new(big.Int).SetInt64(int64(*in.PubkeyY))
	badPub := &ec.PublicKey{Curve: ec.S256(), X: x, Y: y}

	// Any private key will do — the error must come from badPub not being
	// on the curve, checked before the scalar multiplication happens.
	priv, err := ec.PrivateKeyFromHex("0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatalf("%s: PrivateKeyFromHex: %v", v.ID, err)
	}
	_, err = badPub.DeriveSharedSecret(priv)
	if expected.Throws && err == nil {
		t.Errorf("%s: DeriveSharedSecret with off-curve point did not error", v.ID)
	}
}

func pubkeyBRC42(t *testing.T, v conformance.Vector, in publicKeyInput, expected publicKeyExpected) {
	t.Helper()
	senderPriv, err := ec.PrivateKeyFromHex(in.SenderPrivateKeyHex)
	if err != nil {
		t.Fatalf("%s: PrivateKeyFromHex(sender): %v", v.ID, err)
	}
	recipPub, err := ec.PublicKeyFromString(in.RecipientPublicKeyHex)
	if err != nil {
		t.Fatalf("%s: PublicKeyFromString(recipient): %v", v.ID, err)
	}
	derived, err := recipPub.DeriveChild(senderPriv, in.InvoiceNumber)
	if err != nil {
		t.Fatalf("%s: DeriveChild: %v", v.ID, err)
	}
	if gotHex := hex.EncodeToString(derived.Compressed()); gotHex != expected.DerivedPublicKeyHex {
		t.Errorf("%s: derived public key mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, expected.DerivedPublicKeyHex)
	}
}
