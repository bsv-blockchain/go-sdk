package keys_test

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

type keyDerivationInput struct {
	PrivkeyHex             string   `json:"privkey_hex"`
	RecipientPrivateKeyHex string   `json:"recipient_private_key_hex"`
	SenderPublicKeyHex     string   `json:"sender_public_key_hex"`
	SenderPrivateKeyHex    string   `json:"sender_private_key_hex"`
	RecipientPublicKeyHex  string   `json:"recipient_public_key_hex"`
	InvoiceNumber          string   `json:"invoice_number"`
	PubkeyX                *float64 `json:"pubkey_x"`
	PubkeyY                *float64 `json:"pubkey_y"`
	Operation              string   `json:"operation"`
	PubkeyDERHex           string   `json:"pubkey_der_hex"`
}

type keyDerivationExpected struct {
	PrivkeyHexRoundtrip  string `json:"privkey_hex_roundtrip"`
	PubkeyDERPrefix      string `json:"pubkey_der_prefix"`
	PubkeyDERLengthBytes *int   `json:"pubkey_der_length_bytes"`
	DerivedPrivateKeyHex string `json:"derived_private_key_hex"`
	DerivedPublicKeyHex  string `json:"derived_public_key_hex"`
	Throws               bool   `json:"throws"`
}

// TestKeyDerivationConformance covers sdk.keys.key-derivation: PrivateKey
// hex round-trips, BRC-42/BRC-43 private and public child derivation, a
// PublicKey DER-prefix check, and the constructor/ECDH error paths shared
// with public-key.json.
//
// key-016 (direct_constructor) is a GoGap for the same reason as
// public-key.json's pubkey-constructor-err-001: the TS dispatcher skips it
// without asserting, and go-sdk's PublicKey has no ambiguous single-string
// constructor to exercise.
func TestKeyDerivationConformance(t *testing.T) {
	file := conformance.Load(t, "sdk/keys/key-derivation.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in keyDerivationInput
		v.DecodeInput(t, &in)
		var expected keyDerivationExpected
		v.DecodeExpected(t, &expected)

		switch {
		case in.Operation == "direct_constructor":
			conformance.GoGap(t, "TS dispatcher skips direct_constructor shapes without asserting; go-sdk's PublicKey has no ambiguous DER-string constructor to exercise")
		case in.PrivkeyHex != "" && expected.PubkeyDERPrefix != "":
			keyDerivationPubkeyPrefix(t, v, in, expected)
		case in.PrivkeyHex != "":
			keyDerivationPrivkeyRoundtrip(t, v, in, expected)
		case in.RecipientPrivateKeyHex != "":
			keyDerivationPrivateChild(t, v, in, expected)
		case in.PubkeyX != nil:
			keyDerivationECDHError(t, v, in, expected)
		case in.SenderPrivateKeyHex != "":
			keyDerivationPublicChild(t, v, in, expected)
		default:
			t.Fatalf("%s: unrecognized key-derivation vector shape", v.ID)
		}
	})
}

func keyDerivationPrivkeyRoundtrip(t *testing.T, v conformance.Vector, in keyDerivationInput, expected keyDerivationExpected) {
	t.Helper()
	priv, err := ec.PrivateKeyFromHex(in.PrivkeyHex)
	if err != nil {
		t.Fatalf("%s: PrivateKeyFromHex: %v", v.ID, err)
	}
	if got := priv.Hex(); got != expected.PrivkeyHexRoundtrip {
		t.Errorf("%s: hex roundtrip mismatch\ngot:  %s\nwant: %s", v.ID, got, expected.PrivkeyHexRoundtrip)
	}
}

// keyDerivationPubkeyPrefix covers key-015: PublicKey DER compressed
// encoding, checking length and that the prefix byte is 02 or 03 (either is
// valid; which one depends on the y-coordinate's parity).
func keyDerivationPubkeyPrefix(t *testing.T, v conformance.Vector, in keyDerivationInput, expected keyDerivationExpected) {
	t.Helper()
	priv, err := ec.PrivateKeyFromHex(in.PrivkeyHex)
	if err != nil {
		t.Fatalf("%s: PrivateKeyFromHex: %v", v.ID, err)
	}
	der := priv.PubKey().Compressed()
	if expected.PubkeyDERLengthBytes != nil && len(der) != *expected.PubkeyDERLengthBytes {
		t.Errorf("%s: der length = %d bytes, want %d", v.ID, len(der), *expected.PubkeyDERLengthBytes)
	}
	prefix := hex.EncodeToString(der[:1])
	if prefix != "02" && prefix != "03" {
		t.Errorf("%s: der prefix = %s, want 02 or 03", v.ID, prefix)
	}
}

func keyDerivationPrivateChild(t *testing.T, v conformance.Vector, in keyDerivationInput, expected keyDerivationExpected) {
	t.Helper()
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
}

func keyDerivationPublicChild(t *testing.T, v conformance.Vector, in keyDerivationInput, expected keyDerivationExpected) {
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

func keyDerivationECDHError(t *testing.T, v conformance.Vector, in keyDerivationInput, expected keyDerivationExpected) {
	t.Helper()
	x := new(big.Int).SetInt64(int64(*in.PubkeyX))
	y := new(big.Int).SetInt64(int64(*in.PubkeyY))
	badPub := &ec.PublicKey{Curve: ec.S256(), X: x, Y: y}

	priv, err := ec.PrivateKeyFromHex("0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatalf("%s: PrivateKeyFromHex: %v", v.ID, err)
	}
	_, err = badPub.DeriveSharedSecret(priv)
	if expected.Throws && err == nil {
		t.Errorf("%s: DeriveSharedSecret with off-curve point did not error", v.ID)
	}
}
