package crypto_test

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

type ecdsaInput struct {
	PrivkeyHex        string   `json:"privkey_hex"`
	MessageHex        string   `json:"message_hex"`
	SignedMessageHex  string   `json:"signed_message_hex"`
	VerifyMessageHex  string   `json:"verify_message_hex"`
	K                 string   `json:"k"`
	KFunction         string   `json:"k_function"`
	ForceLowS         bool     `json:"force_low_s"`
	Operation         string   `json:"operation"`
	KHex              string   `json:"k_hex"`
	Pubkey            string   `json:"pubkey"`
	WrongPubkeyScalar string   `json:"wrong_pubkey_scalar"`
	SignatureR        string   `json:"signature_r"`
	SignatureS        string   `json:"signature_s"`
	MessageTooLarge   bool     `json:"message_too_large"`
	MessageBits       int      `json:"message_bits"`
	UseValidSignature bool     `json:"use_valid_signature"`
	Messages          []string `json:"messages"`
}

// TestECDSAConformance covers sdk.crypto.ecdsa. Vectors that supply a
// literal custom k (anything other than "drbg") or a k_function are GoGap'd:
// the TS reference dispatcher itself (dispatchECDSA in sdk.ts) returns
// before asserting anything for those shapes — "Custom k values require
// TS-specific API — skip gracefully" — and go-sdk's public secp256k1 signing
// API (ec.PrivateKey.Sign) has no equivalent custom-nonce parameter, so
// there is nothing to assert cross-language for those cases either.
func TestECDSAConformance(t *testing.T) {
	file := conformance.Load(t, "sdk/crypto/ecdsa.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in ecdsaInput
		v.DecodeInput(t, &in)

		if in.KFunction != "" {
			conformance.GoGap(t, "TS dispatcher skips k_function shapes without asserting; go-sdk's ec.PrivateKey.Sign has no custom-nonce-callback API to exercise")
			return
		}
		if in.K != "" && in.K != "drbg" {
			conformance.GoGap(t, "TS dispatcher skips literal custom-k shapes without asserting; go-sdk's public secp256k1 Sign API has no custom-nonce parameter to exercise")
			return
		}

		switch {
		case in.MessageTooLarge:
			ecdsaMessageTooLarge(t, v, in)
		case in.Pubkey == "infinity":
			ecdsaPubkeyInfinity(t, v, in)
		case in.Operation != "":
			ecdsaCurveOp(t, v, in)
		case in.SignatureR != "":
			ecdsaExplicitSignatureVerify(t, v, in)
		case len(in.Messages) > 0:
			ecdsaBatchMessages(t, v, in)
		case in.WrongPubkeyScalar != "":
			ecdsaWrongPubkey(t, v, in)
		case in.PrivkeyHex != "":
			ecdsaSignAndVerify(t, v, in)
		default:
			t.Fatalf("%s: unrecognized ecdsa vector shape", v.ID)
		}
	})
}

func ecdsaMessageTooLarge(t *testing.T, v conformance.Vector, in ecdsaInput) {
	t.Helper()
	priv, err := ec.PrivateKeyFromHex(in.PrivkeyHex)
	if err != nil {
		t.Fatalf("%s: PrivateKeyFromHex: %v", v.ID, err)
	}
	bits := in.MessageBits
	if bits == 0 {
		bits = 258
	}
	bigMsg := new(big.Int).Lsh(big.NewInt(1), uint(bits))

	var expected struct {
		Verify bool `json:"verify"`
		Throws bool `json:"throws"`
	}
	v.DecodeExpected(t, &expected)

	if in.UseValidSignature {
		normalMsg, _ := hex.DecodeString("deadbeef")
		sig, signErr := priv.Sign(normalMsg)
		if signErr != nil {
			t.Fatalf("%s: Sign: %v", v.ID, signErr)
		}
		if got := sig.Verify(bigMsg.Bytes(), priv.PubKey()); got != expected.Verify {
			t.Errorf("%s: verify(oversized) = %v, want %v", v.ID, got, expected.Verify)
		}
		return
	}

	_, err = priv.Sign(bigMsg.Bytes())
	if expected.Throws && err == nil {
		t.Errorf("%s: Sign(oversized message) did not error", v.ID)
	}
	if !expected.Throws && err != nil {
		t.Errorf("%s: Sign(oversized message) unexpectedly errored: %v", v.ID, err)
	}
}

func ecdsaPubkeyInfinity(t *testing.T, v conformance.Vector, in ecdsaInput) {
	t.Helper()
	priv, err := ec.PrivateKeyFromHex(in.PrivkeyHex)
	if err != nil {
		t.Fatalf("%s: PrivateKeyFromHex: %v", v.ID, err)
	}
	msgHex := in.MessageHex
	if msgHex == "" {
		msgHex = in.SignedMessageHex
	}
	msg := hexOrEmpty(t, v.ID, "message_hex", msgHex)
	sig, err := priv.Sign(msg)
	if err != nil {
		t.Fatalf("%s: Sign: %v", v.ID, err)
	}

	var expected struct {
		Throws bool `json:"throws"`
	}
	v.DecodeExpected(t, &expected)

	infKey := &ec.PublicKey{Curve: ec.S256()}
	// ec.Signature.Verify has no error return; an infinite/invalid public
	// key must make verification fail (false) rather than validate or
	// panic, which is the closest Go equivalent to the TS reference
	// throwing "Invalid public key".
	got := sig.Verify(msg, infKey)
	if expected.Throws && got {
		t.Errorf("%s: verify against point-at-infinity pubkey returned true, want false (TS throws)", v.ID)
	}
	if !expected.Throws && !got {
		t.Errorf("%s: verify against point-at-infinity pubkey returned false, want true", v.ID)
	}
}

func ecdsaCurveOp(t *testing.T, v conformance.Vector, in ecdsaInput) {
	t.Helper()
	var expected struct {
		IsInfinity bool `json:"is_infinity"`
	}
	v.DecodeExpected(t, &expected)

	switch in.Operation {
	case "point_add_negation":
		k := new(big.Int)
		k.SetString(in.KHex, 16)
		kx, ky := ec.S256().ScalarBaseMult(k.Bytes())
		negY := new(big.Int).Sub(ec.S256().Params().P, ky)
		rx, ry := ec.S256().Add(kx, ky, kx, negY)
		gotInfinity := rx.Sign() == 0 && ry.Sign() == 0
		if gotInfinity != expected.IsInfinity {
			t.Errorf("%s: k*G + (-k*G) is_infinity = %v, want %v", v.ID, gotInfinity, expected.IsInfinity)
		}
	case "scalar_mul_zero":
		k := hexOrEmpty(t, v.ID, "k_hex", in.KHex)
		zx, zy := ec.S256().ScalarBaseMult(k)
		gotInfinity := zx.Sign() == 0 && zy.Sign() == 0
		if gotInfinity != expected.IsInfinity {
			t.Errorf("%s: 0*G is_infinity = %v, want %v", v.ID, gotInfinity, expected.IsInfinity)
		}
	default:
		t.Fatalf("%s: unknown curve operation %q", v.ID, in.Operation)
	}
}

func ecdsaExplicitSignatureVerify(t *testing.T, v conformance.Vector, in ecdsaInput) {
	t.Helper()
	r := new(big.Int).SetBytes(hexOrEmpty(t, v.ID, "signature_r", in.SignatureR))
	s := new(big.Int).SetBytes(hexOrEmpty(t, v.ID, "signature_s", in.SignatureS))
	sig := &ec.Signature{R: r, S: s}

	priv, err := ec.PrivateKeyFromHex(in.PrivkeyHex)
	if err != nil {
		t.Fatalf("%s: PrivateKeyFromHex: %v", v.ID, err)
	}
	msg := hexOrEmpty(t, v.ID, "message_hex", in.MessageHex)

	// Note: the vectors in this file key the expected outcome as "verify"
	// (not "valid", which the upstream TS dispatcher's
	// ecdsaExplicitSignatureVerify actually reads — a field-name mismatch
	// that makes it silently check against the getBool default of false).
	// We assert against the vector's documented "verify" field directly,
	// since that reflects the vector's actual intent.
	var expected struct {
		Verify bool `json:"verify"`
	}
	v.DecodeExpected(t, &expected)

	if got := sig.Verify(msg, priv.PubKey()); got != expected.Verify {
		t.Errorf("%s: verify(r=%s, s=%s) = %v, want %v", v.ID, in.SignatureR, in.SignatureS, got, expected.Verify)
	}
}

func ecdsaBatchMessages(t *testing.T, v conformance.Vector, in ecdsaInput) {
	t.Helper()
	priv, err := ec.PrivateKeyFromHex(in.PrivkeyHex)
	if err != nil {
		t.Fatalf("%s: PrivateKeyFromHex: %v", v.ID, err)
	}

	var expected struct {
		AllSLteHalfN bool `json:"all_s_lte_half_n"`
	}
	v.DecodeExpected(t, &expected)

	halfN := new(big.Int).Rsh(ec.S256().N, 1)
	for _, mh := range in.Messages {
		msg := hexOrEmpty(t, v.ID, "messages[]", mh)
		sig, err := priv.Sign(msg)
		if err != nil {
			t.Fatalf("%s: Sign(%s): %v", v.ID, mh, err)
		}
		sLteHalf := sig.S.Cmp(halfN) <= 0
		if expected.AllSLteHalfN && !sLteHalf {
			t.Errorf("%s: message %s: s > n/2 despite forceLowS", v.ID, mh)
		}
	}
}

func ecdsaWrongPubkey(t *testing.T, v conformance.Vector, in ecdsaInput) {
	t.Helper()
	priv, err := ec.PrivateKeyFromHex(in.PrivkeyHex)
	if err != nil {
		t.Fatalf("%s: PrivateKeyFromHex: %v", v.ID, err)
	}
	msgHex := in.MessageHex
	if msgHex == "" {
		msgHex = in.SignedMessageHex
	}
	msg := hexOrEmpty(t, v.ID, "message_hex", msgHex)
	sig, err := priv.Sign(msg)
	if err != nil {
		t.Fatalf("%s: Sign: %v", v.ID, err)
	}

	scalar := new(big.Int)
	if _, ok := scalar.SetString(in.WrongPubkeyScalar, 10); !ok {
		t.Fatalf("%s: bad wrong_pubkey_scalar %q", v.ID, in.WrongPubkeyScalar)
	}
	wrongPriv, err := ec.PrivateKeyFromHex(hex.EncodeToString(leftPad32(scalar.Bytes())))
	if err != nil {
		t.Fatalf("%s: PrivateKeyFromHex(wrong scalar): %v", v.ID, err)
	}

	var expected struct {
		Verify bool `json:"verify"`
	}
	v.DecodeExpected(t, &expected)

	if got := sig.Verify(msg, wrongPriv.PubKey()); got != expected.Verify {
		t.Errorf("%s: verify with wrong pubkey = %v, want %v", v.ID, got, expected.Verify)
	}
}

func ecdsaSignAndVerify(t *testing.T, v conformance.Vector, in ecdsaInput) {
	t.Helper()
	priv, err := ec.PrivateKeyFromHex(in.PrivkeyHex)
	if err != nil {
		t.Fatalf("%s: PrivateKeyFromHex: %v", v.ID, err)
	}
	msgHex := in.MessageHex
	if msgHex == "" {
		msgHex = in.SignedMessageHex
	}
	msg := hexOrEmpty(t, v.ID, "message_hex", msgHex)

	var expected struct {
		Throws                bool  `json:"throws"`
		Valid                 *bool `json:"valid"`
		Verify                *bool `json:"verify"`
		DERLengthBytes        *int  `json:"der_length_bytes"`
		DERHexLengthChars     *int  `json:"der_hex_length_chars"`
		RoundtripREqualSEqual bool  `json:"roundtrip_r_s_equal"`
		SLteHalfN             bool  `json:"s_lte_half_n"`
	}
	v.DecodeExpected(t, &expected)

	sig, err := priv.Sign(msg)
	if expected.Throws {
		if err == nil {
			t.Errorf("%s: Sign did not error, want error", v.ID)
		}
		return
	}
	if err != nil {
		t.Fatalf("%s: Sign: %v", v.ID, err)
	}

	verifyMsgHex := in.VerifyMessageHex
	if verifyMsgHex == "" {
		verifyMsgHex = msgHex
	}
	verifyMsg := hexOrEmpty(t, v.ID, "verify_message_hex", verifyMsgHex)

	wantValid := expected.Valid
	if wantValid == nil {
		wantValid = expected.Verify
	}
	if wantValid != nil {
		if got := sig.Verify(verifyMsg, priv.PubKey()); got != *wantValid {
			t.Errorf("%s: verify = %v, want %v", v.ID, got, *wantValid)
		}
	}
	if expected.DERLengthBytes != nil {
		if got := len(sig.Serialize()); got != *expected.DERLengthBytes {
			t.Errorf("%s: der length = %d bytes, want %d", v.ID, got, *expected.DERLengthBytes)
		}
	}
	if expected.DERHexLengthChars != nil {
		if got := len(hex.EncodeToString(sig.Serialize())); got != *expected.DERHexLengthChars {
			t.Errorf("%s: der hex length = %d chars, want %d", v.ID, got, *expected.DERHexLengthChars)
		}
	}
	if expected.RoundtripREqualSEqual {
		der := sig.Serialize()
		sig2, err := ec.ParseDERSignature(der)
		if err != nil {
			t.Fatalf("%s: ParseDERSignature: %v", v.ID, err)
		}
		if sig.R.Cmp(sig2.R) != 0 || sig.S.Cmp(sig2.S) != 0 {
			t.Errorf("%s: DER roundtrip r/s mismatch", v.ID)
		}
	}
	if expected.SLteHalfN {
		halfN := new(big.Int).Rsh(ec.S256().N, 1)
		if sig.S.Cmp(halfN) > 0 {
			t.Errorf("%s: s > n/2 despite forceLowS", v.ID)
		}
	}
}

// leftPad32 left-pads b with zero bytes to 32 bytes, matching how a scalar
// integer is rendered as a private key hex string.
func leftPad32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
