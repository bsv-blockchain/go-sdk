// Package regressions_test runs the ts-stack regressions/*.json conformance
// vectors assigned to the storage/overlay/sync domain against go-sdk.
package regressions_test

import (
	"encoding/hex"
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	"github.com/bsv-blockchain/go-sdk/storage"
)

// TestRegressionBIP276HexDecode: every vector in this file carries
// parity_class "intended" at the vector level (Go-SDK-only bug, no TS
// dispatcher path exists), so conformance.Run governed-skips them all. This
// test exists to prove the file loads and stays governed-skipped rather than
// silently starting to run (which would mean the corpus changed underneath
// us). BIP276 itself already carries the fix described in the vectors
// (script/bip276.go uses a hex-aware regex and base-16 parsing) but
// script/** belongs to a different domain owner, so no production changes
// are made here.
func TestRegressionBIP276HexDecode(t *testing.T) {
	f := conformance.Load(t, "regressions/bip276-hex-decode.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		t.Fatalf("vector %s ran instead of being governed-skipped; expected vector-level "+
			"parity_class \"intended\" throughout bip276-hex-decode.json", v.ID)
	})
}

type uhrpParityInput struct {
	HashHex string `json:"hash_hex"`
	URL     string `json:"url"`
}

type uhrpParityExpected struct {
	URL     string `json:"url"`
	HashHex string `json:"hash_hex"`
	Valid   *bool  `json:"valid"`
	Error   string `json:"error"`
}

// TestRegressionUHRPURLParity re-runs the go-sdk#310 regression: Go's
// storage.GetURLForHash/GetHashFromURL/IsValidURL must produce byte-for-byte
// identical Base58Check UHRP URLs to the TypeScript SDK for the same input.
func TestRegressionUHRPURLParity(t *testing.T) {
	f := conformance.Load(t, "regressions/uhrp-url-parity.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		var in uhrpParityInput
		v.DecodeInput(t, &in)
		var exp uhrpParityExpected
		v.DecodeExpected(t, &exp)

		switch {
		case in.HashHex != "" && exp.URL != "":
			hash, err := hex.DecodeString(in.HashHex)
			if err != nil {
				t.Fatalf("decode hash_hex: %v", err)
			}
			got, err := storage.GetURLForHash(hash)
			if err != nil {
				t.Fatalf("GetURLForHash: %v", err)
			}
			if got != exp.URL {
				t.Errorf("GetURLForHash(%s) = %q, want %q", in.HashHex, got, exp.URL)
			}

		case in.URL != "" && exp.HashHex != "":
			got, err := storage.GetHashFromURL(in.URL)
			if err != nil {
				t.Fatalf("GetHashFromURL(%q): %v", in.URL, err)
			}
			if hex.EncodeToString(got) != exp.HashHex {
				t.Errorf("GetHashFromURL(%q) = %x, want %s", in.URL, got, exp.HashHex)
			}

		case in.URL != "" && exp.Valid != nil:
			got := storage.IsValidURL(in.URL)
			if got != *exp.Valid {
				t.Errorf("IsValidURL(%q) = %v, want %v", in.URL, got, *exp.Valid)
			}
			if !*exp.Valid {
				if _, err := storage.GetHashFromURL(in.URL); err == nil {
					t.Errorf("GetHashFromURL(%q) succeeded, want an error (%s)", in.URL, exp.Error)
				}
			}

		default:
			t.Fatalf("unrecognized uhrp-url-parity vector shape: input=%+v expected=%+v", in, exp)
		}
	})
}
