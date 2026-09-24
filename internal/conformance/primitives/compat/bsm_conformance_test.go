// Package compat_test runs the ts-stack conformance corpus for go-sdk's
// Bitcoin Signed Message (BSM) compat layer against sdk/compat/bsm.json.
package compat_test

import (
	"encoding/hex"
	"testing"

	bsm "github.com/bsv-blockchain/go-sdk/compat/bsm"
	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

type bsmInput struct {
	MessageHex    string `json:"message_hex"`
	PrivkeyHex    string `json:"privkey_hex"`
	PrivkeyWIF    string `json:"privkey_wif"`
	PubkeyHex     string `json:"pubkey_hex"`
	Encoding      string `json:"encoding"`
	DERHex        string `json:"der_hex"`
	CompactSigHex string `json:"compact_sig_hex"`
	MagicHashHex  string `json:"magic_hash_hex"`
}

func mustHexBSM(t *testing.T, id, field, s string) []byte {
	t.Helper()
	if len(s)%2 != 0 {
		s = "0" + s
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("%s: decode %s %q: %v", id, field, s, err)
	}
	return b
}

// TestBSMConformance covers sdk.compat.bsm: magicHash, sign, verify, and
// public-key recovery, against compat/bsm and primitives/ec.
func TestBSMConformance(t *testing.T) {
	file := conformance.Load(t, "sdk/compat/bsm.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in bsmInput
		v.DecodeInput(t, &in)
		msg := mustHexBSM(t, v.ID, "message_hex", in.MessageHex)

		switch {
		case in.DERHex != "":
			bsmVerifyDER(t, v, in, msg)
		case in.CompactSigHex != "":
			bsmCompactVerifyOrRecover(t, v, in, msg)
		case in.PrivkeyHex != "" || in.PrivkeyWIF != "":
			bsmSign(t, v, in, msg)
		case in.PrivkeyHex == "" && in.PrivkeyWIF == "":
			bsmMagicHash(t, v, msg)
		default:
			t.Fatalf("%s: unrecognized bsm vector shape", v.ID)
		}
	})
}

func bsmMagicHash(t *testing.T, v conformance.Vector, msg []byte) {
	t.Helper()
	var expected struct {
		MagicHashHex         string `json:"magic_hash_hex"`
		MagicHashLengthBytes *int   `json:"magic_hash_length_bytes"`
	}
	v.DecodeExpected(t, &expected)

	got := bsm.MagicHash(msg)
	if gotHex := hex.EncodeToString(got); gotHex != expected.MagicHashHex {
		t.Errorf("%s: magic hash mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, expected.MagicHashHex)
	}
	if expected.MagicHashLengthBytes != nil && len(got) != *expected.MagicHashLengthBytes {
		t.Errorf("%s: magic hash length = %d, want %d", v.ID, len(got), *expected.MagicHashLengthBytes)
	}
}

func bsmSign(t *testing.T, v conformance.Vector, in bsmInput, msg []byte) {
	t.Helper()
	var expected struct {
		DERHex           string `json:"der_hex"`
		DERLengthBytes   *int   `json:"der_length_bytes"`
		Base64CompactSig string `json:"base64_compact_sig"`
	}
	v.DecodeExpected(t, &expected)

	switch in.Encoding {
	case "raw":
		priv, err := ec.PrivateKeyFromHex(in.PrivkeyHex)
		if err != nil {
			t.Fatalf("%s: PrivateKeyFromHex: %v", v.ID, err)
		}
		sig, err := priv.Sign(bsm.MagicHash(msg))
		if err != nil {
			t.Fatalf("%s: Sign: %v", v.ID, err)
		}
		der := sig.Serialize()
		if expected.DERHex != "" {
			if gotHex := hex.EncodeToString(der); gotHex != expected.DERHex {
				t.Errorf("%s: der mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, expected.DERHex)
			}
		}
		if expected.DERLengthBytes != nil && len(der) != *expected.DERLengthBytes {
			t.Errorf("%s: der length = %d, want %d", v.ID, len(der), *expected.DERLengthBytes)
		}
	case "base64":
		var priv *ec.PrivateKey
		var err error
		if in.PrivkeyWIF != "" {
			priv, err = ec.PrivateKeyFromWif(in.PrivkeyWIF)
		} else {
			priv, err = ec.PrivateKeyFromHex(in.PrivkeyHex)
		}
		if err != nil {
			t.Fatalf("%s: decode private key: %v", v.ID, err)
		}
		got, err := bsm.SignMessageString(priv, msg)
		if err != nil {
			t.Fatalf("%s: SignMessageString: %v", v.ID, err)
		}
		if got != expected.Base64CompactSig {
			t.Errorf("%s: base64 compact sig mismatch\ngot:  %s\nwant: %s", v.ID, got, expected.Base64CompactSig)
		}
	default:
		t.Fatalf("%s: unknown sign encoding %q", v.ID, in.Encoding)
	}
}

func bsmVerifyDER(t *testing.T, v conformance.Vector, in bsmInput, msg []byte) {
	t.Helper()
	var expected struct {
		Valid bool `json:"valid"`
	}
	v.DecodeExpected(t, &expected)

	der := mustHexBSM(t, v.ID, "der_hex", in.DERHex)
	pub, err := ec.PublicKeyFromString(in.PubkeyHex)
	if err != nil {
		t.Fatalf("%s: PublicKeyFromString: %v", v.ID, err)
	}
	sig, err := ec.ParseDERSignature(der)
	if err != nil {
		if expected.Valid {
			t.Errorf("%s: ParseDERSignature unexpectedly errored: %v", v.ID, err)
		}
		return
	}
	if got := sig.Verify(bsm.MagicHash(msg), pub); got != expected.Valid {
		t.Errorf("%s: verify = %v, want %v", v.ID, got, expected.Valid)
	}
}

func bsmCompactVerifyOrRecover(t *testing.T, v conformance.Vector, in bsmInput, msg []byte) {
	t.Helper()
	compact := mustHexBSM(t, v.ID, "compact_sig_hex", in.CompactSigHex)
	// Recompute the magic hash from the message rather than relying on the
	// vector's own precomputed magic_hash_hex field (only bsm-recovery-001
	// supplies it) — bsm-magic-* already conformance-checks MagicHash
	// itself, and doing so here keeps this path exercising real production
	// code for every compact-signature vector.
	magicHash := bsm.MagicHash(msg)
	if in.MagicHashHex != "" {
		if gotHex := hex.EncodeToString(magicHash); gotHex != in.MagicHashHex {
			t.Errorf("%s: recomputed magic hash %s does not match vector's magic_hash_hex %s", v.ID, gotHex, in.MagicHashHex)
		}
	}

	var expected struct {
		Valid              *bool  `json:"valid"`
		RecoveryFactor     *int   `json:"recovery_factor"`
		RecoveredPubkeyHex string `json:"recovered_pubkey_hex"`
	}
	v.DecodeExpected(t, &expected)

	if expected.Valid != nil {
		pub, err := ec.PublicKeyFromString(in.PubkeyHex)
		if err != nil {
			t.Fatalf("%s: PublicKeyFromString: %v", v.ID, err)
		}
		sig, err := ec.SignatureFromCompact(compact)
		if err != nil {
			if *expected.Valid {
				t.Errorf("%s: SignatureFromCompact unexpectedly errored: %v", v.ID, err)
			}
			return
		}
		if got := sig.Verify(magicHash, pub); got != *expected.Valid {
			t.Errorf("%s: verify = %v, want %v", v.ID, got, *expected.Valid)
		}
	}

	if expected.RecoveryFactor != nil || expected.RecoveredPubkeyHex != "" {
		if got := int((compact[0] - 27) &^ 4); expected.RecoveryFactor != nil && got != *expected.RecoveryFactor {
			t.Errorf("%s: recovery factor = %d, want %d", v.ID, got, *expected.RecoveryFactor)
		}
		if expected.RecoveredPubkeyHex != "" {
			pub, _, err := ec.RecoverCompact(compact, magicHash)
			if err != nil {
				t.Fatalf("%s: RecoverCompact: %v", v.ID, err)
			}
			if gotHex := hex.EncodeToString(pub.Compressed()); gotHex != expected.RecoveredPubkeyHex {
				t.Errorf("%s: recovered pubkey mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, expected.RecoveredPubkeyHex)
			}
		}
	}
}
