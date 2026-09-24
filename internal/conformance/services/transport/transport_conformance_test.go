// Package transport_test runs the ts-stack transport/air-gap-optical.json
// conformance vectors against go-sdk.
package transport_test

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
)

// TestTransportAirGapOptical declares a GoGap for every vector. The BRC-141
// air-gap optical transport (deterministic fountain-coded QR part
// encoding/decoding, session locking, hostile-input rejection) is
// implemented in ts-stack by the standalone @bsv/air-gap package; go-sdk has
// no port of it (no fountain coding, part framing, or optical transport code
// anywhere in this repository). Building the protocol from scratch is a new
// implementation, out of scope for a conformance-parity fix.
func TestTransportAirGapOptical(t *testing.T) {
	f := conformance.Load(t, "transport/air-gap-optical.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		conformance.GoGap(t, "go-sdk has no @bsv/air-gap port (fountain-coded part encoding/decoding, "+
			"session locking); no air-gap/optical transport code exists anywhere in this repository")
	})
}
