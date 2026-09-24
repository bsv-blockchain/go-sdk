// Package regressions_test runs the ts-stack conformance corpus's
// primitives-owned regression vectors.
package regressions_test

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// TestPrivateKeyModularReductionConformance covers
// regressions/privatekey-modular-reduction.json (ts-sdk#31). Vectors .0002
// and .0003 are governed skips in the vector file itself (parity_class
// "intended"): they document a known go-sdk gap — PrivateKeyFromBytes does
// not reduce a scalar in [n, 2n) modulo the curve order, nor reject a
// scalar == n — that conformance.Run skips automatically. Only .0001
// (an in-range scalar) is exercised here.
func TestPrivateKeyModularReductionConformance(t *testing.T) {
	file := conformance.Load(t, "regressions/privatekey-modular-reduction.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in struct {
			ScalarHex string `json:"scalar_hex"`
		}
		v.DecodeInput(t, &in)
		var expected struct {
			WIF string `json:"wif"`
		}
		v.DecodeExpected(t, &expected)

		priv, err := ec.PrivateKeyFromHex(in.ScalarHex)
		if err != nil {
			t.Fatalf("%s: PrivateKeyFromHex: %v", v.ID, err)
		}
		if got := priv.Wif(); got != expected.WIF {
			t.Errorf("%s: WIF mismatch\ngot:  %s\nwant: %s", v.ID, got, expected.WIF)
		}
	})
}
