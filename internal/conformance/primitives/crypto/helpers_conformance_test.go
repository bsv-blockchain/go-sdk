// Package crypto_test runs the ts-stack conformance corpus for go-sdk's
// low-level hash and cipher primitives against sdk/crypto/*.json.
package crypto_test

import (
	"encoding/hex"
	"testing"
)

// tsHexDecode decodes a hex string the way the TS runner's hexToBytes
// (sdk.ts) does: an odd-length string is left-padded with a leading "0"
// before decoding, rather than rejected. A handful of vectors (e.g.
// ecdsa-003's verify_message_hex) rely on this leniency.
func tsHexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		s = "0" + s
	}
	return hex.DecodeString(s)
}

// mustHex decodes s as hex (TS-lenient), failing the test on error.
func mustHex(t *testing.T, id, field, s string) []byte {
	t.Helper()
	b, err := tsHexDecode(s)
	if err != nil {
		t.Fatalf("%s: decode %s %q: %v", id, field, s, err)
	}
	return b
}

// hexOrEmpty decodes s as hex (TS-lenient), treating "" as an empty slice.
func hexOrEmpty(t *testing.T, id, field, s string) []byte {
	t.Helper()
	if s == "" {
		return nil
	}
	return mustHex(t, id, field, s)
}

// decodeMessage decodes an input message per its declared encoding, mirroring
// the TS runner's decodeMessage (sdk.ts): hex is hex-decoded (TS-lenient),
// anything else is treated as raw UTF-8 bytes.
func decodeMessage(t *testing.T, msg, encoding string) []byte {
	t.Helper()
	if encoding == "hex" {
		return mustHex(t, "", "message", msg)
	}
	return []byte(msg)
}
