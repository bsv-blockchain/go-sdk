package crypto_test

import (
	"encoding/hex"
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

type signatureInput struct {
	PrivkeyHex  string `json:"privkey_hex"`
	MessageHex  string `json:"message_hex"`
	DERHex      string `json:"der_hex"`
	DERBytesHex string `json:"der_bytes_hex"`
	CompactHex  string `json:"compact_hex"`
	Recovery    *int   `json:"recovery"`
	Compressed  bool   `json:"compressed"`
	ByteCount   *int   `json:"byte_count"`
	FirstByteIn *int   `json:"first_byte"`
}

type signatureExpected struct {
	DERHex                string `json:"der_hex"`
	DERLengthBytes        *int   `json:"der_length_bytes"`
	RHex                  string `json:"r_hex"`
	SHex                  string `json:"s_hex"`
	Throws                bool   `json:"throws"`
	CompactHex            string `json:"compact_hex"`
	CompactLengthBytes    *int   `json:"compact_length_bytes"`
	CompactLengthHexChars *int   `json:"compact_length_hex_chars"`
	FirstByte             *int   `json:"first_byte"`
}

// TestSignatureConformance covers sdk.crypto.signature: DER encode/decode,
// compact encode/decode, and their error paths, against go-sdk's
// primitives/ec.Signature.
func TestSignatureConformance(t *testing.T) {
	file := conformance.Load(t, "sdk/crypto/signature.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in signatureInput
		v.DecodeInput(t, &in)
		var expected signatureExpected
		v.DecodeExpected(t, &expected)

		switch {
		case in.PrivkeyHex != "" && in.MessageHex != "":
			sigFromPrivkey(t, v, in, expected)
		case in.DERHex != "":
			sigFromDER(t, v, in, expected)
		case in.DERBytesHex != "":
			sigFromDERBytesThrows(t, v, in, expected)
		case in.CompactHex != "":
			sigFromCompact(t, v, in, expected)
		case in.ByteCount != nil:
			sigCompactWrongLength(t, v, *in.ByteCount, expected)
		case in.FirstByteIn != nil:
			sigCompactBadHeaderByte(t, v, *in.FirstByteIn, expected)
		default:
			t.Fatalf("%s: unrecognized signature vector shape", v.ID)
		}
	})
}

func sigFromPrivkey(t *testing.T, v conformance.Vector, in signatureInput, expected signatureExpected) {
	t.Helper()
	priv, err := ec.PrivateKeyFromHex(in.PrivkeyHex)
	if err != nil {
		t.Fatalf("%s: PrivateKeyFromHex: %v", v.ID, err)
	}
	msg := hexOrEmpty(t, v.ID, "message_hex", in.MessageHex)

	if in.Recovery != nil && expected.Throws && (*in.Recovery < 0 || *in.Recovery > 3) {
		// sig-tocompact-err-001/002: toCompact must reject an out-of-range
		// recovery id.
		sig, signErr := priv.Sign(msg)
		if signErr != nil {
			t.Fatalf("%s: Sign: %v", v.ID, signErr)
		}
		if _, compactErr := sig.ToCompact(*in.Recovery, in.Compressed); compactErr == nil {
			t.Errorf("%s: ToCompact(recovery=%d) did not error", v.ID, *in.Recovery)
		}
		return
	}

	sig, err := priv.Sign(msg)
	if err != nil {
		t.Fatalf("%s: Sign: %v", v.ID, err)
	}

	if expected.DERHex != "" {
		if gotHex := hex.EncodeToString(sig.Serialize()); gotHex != expected.DERHex {
			t.Errorf("%s: der mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, expected.DERHex)
		}
	}
	if expected.DERLengthBytes != nil {
		if got := len(sig.Serialize()); got != *expected.DERLengthBytes {
			t.Errorf("%s: der length = %d, want %d", v.ID, got, *expected.DERLengthBytes)
		}
	}
	if expected.RHex != "" && expected.CompactHex == "" && expected.FirstByte == nil {
		if gotHex := hex.EncodeToString(sig.R.Bytes()); gotHex != expected.RHex {
			t.Errorf("%s: r mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, expected.RHex)
		}
	}
	if expected.SHex != "" && expected.CompactHex == "" && expected.FirstByte == nil {
		if gotHex := hex.EncodeToString(sig.S.Bytes()); gotHex != expected.SHex {
			t.Errorf("%s: s mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, expected.SHex)
		}
	}

	if in.Recovery == nil {
		return
	}
	compact, err := sig.ToCompact(*in.Recovery, in.Compressed)
	if err != nil {
		t.Fatalf("%s: ToCompact: %v", v.ID, err)
	}
	if expected.CompactHex != "" {
		if gotHex := hex.EncodeToString(compact); gotHex != expected.CompactHex {
			t.Errorf("%s: compact mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, expected.CompactHex)
		}
	}
	if expected.CompactLengthBytes != nil && len(compact) != *expected.CompactLengthBytes {
		t.Errorf("%s: compact length = %d bytes, want %d", v.ID, len(compact), *expected.CompactLengthBytes)
	}
	if expected.CompactLengthHexChars != nil && len(hex.EncodeToString(compact)) != *expected.CompactLengthHexChars {
		t.Errorf("%s: compact hex length = %d chars, want %d", v.ID, len(hex.EncodeToString(compact)), *expected.CompactLengthHexChars)
	}
	if expected.FirstByte != nil && int(compact[0]) != *expected.FirstByte {
		t.Errorf("%s: compact first byte = %d, want %d", v.ID, compact[0], *expected.FirstByte)
	}
}

func sigFromDER(t *testing.T, v conformance.Vector, in signatureInput, expected signatureExpected) {
	t.Helper()
	der := hexOrEmpty(t, v.ID, "der_hex", in.DERHex)
	sig, err := ec.ParseDERSignature(der)
	if expected.Throws {
		if err == nil {
			t.Errorf("%s: ParseDERSignature did not error", v.ID)
		}
		return
	}
	if err != nil {
		t.Fatalf("%s: ParseDERSignature: %v", v.ID, err)
	}
	if expected.RHex != "" {
		if gotHex := hex.EncodeToString(sig.R.Bytes()); gotHex != expected.RHex {
			t.Errorf("%s: r mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, expected.RHex)
		}
	}
	if expected.SHex != "" {
		if gotHex := hex.EncodeToString(sig.S.Bytes()); gotHex != expected.SHex {
			t.Errorf("%s: s mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, expected.SHex)
		}
	}
}

func sigFromDERBytesThrows(t *testing.T, v conformance.Vector, in signatureInput, expected signatureExpected) {
	t.Helper()
	der := hexOrEmpty(t, v.ID, "der_bytes_hex", in.DERBytesHex)
	_, err := ec.ParseDERSignature(der)
	if expected.Throws && err == nil {
		t.Errorf("%s: ParseDERSignature(%x) did not error", v.ID, der)
	}
}

func sigFromCompact(t *testing.T, v conformance.Vector, in signatureInput, expected signatureExpected) {
	t.Helper()
	compact := hexOrEmpty(t, v.ID, "compact_hex", in.CompactHex)
	// The vector data only exercises r/s extraction, not key recovery, so
	// SignatureFromCompact (a pure decode) is the right match for the TS
	// reference's Signature.fromCompact rather than RecoverCompact.
	sig, err := ec.SignatureFromCompact(compact)
	if err != nil {
		t.Fatalf("%s: SignatureFromCompact: %v", v.ID, err)
	}
	if expected.RHex != "" {
		if gotHex := hex.EncodeToString(sig.R.Bytes()); gotHex != expected.RHex {
			t.Errorf("%s: r mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, expected.RHex)
		}
	}
	if expected.SHex != "" {
		if gotHex := hex.EncodeToString(sig.S.Bytes()); gotHex != expected.SHex {
			t.Errorf("%s: s mismatch\ngot:  %s\nwant: %s", v.ID, gotHex, expected.SHex)
		}
	}
}

// sigCompactWrongLength covers sig-compact-003/004: fromCompact must reject
// input that is not exactly 65 bytes. The vectors describe the input as
// "64 zero bytes" / "66 zero bytes" (byte_count) rather than giving a hex
// string.
func sigCompactWrongLength(t *testing.T, v conformance.Vector, byteCount int, expected signatureExpected) {
	t.Helper()
	_, err := ec.SignatureFromCompact(make([]byte, byteCount))
	if expected.Throws && err == nil {
		t.Errorf("%s: SignatureFromCompact(%d zero bytes) did not error", v.ID, byteCount)
	}
}

// sigCompactBadHeaderByte covers sig-compact-005/006: fromCompact must
// reject a header byte outside [27, 34], regardless of the remaining bytes.
func sigCompactBadHeaderByte(t *testing.T, v conformance.Vector, firstByte int, expected signatureExpected) {
	t.Helper()
	buf := make([]byte, 65)
	buf[0] = byte(firstByte) //nolint:gosec // G115 -- test-only header byte, always 26 or 35 per the vector
	_, err := ec.SignatureFromCompact(buf)
	if expected.Throws && err == nil {
		t.Errorf("%s: SignatureFromCompact(first_byte=%d) did not error", v.ID, firstByte)
	}
}
