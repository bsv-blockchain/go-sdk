package storage_test

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
)

// TestStorageCHIRP declares a GoGap for every storage.chirp-v1 vector.
// CHIRP (Content Hash Indexed Retrieval Protocol) is implemented in
// ts-stack by the standalone @bsv/chirp package (CHIRPBuilder,
// buildBranchLevels), which has no Go port anywhere in this repository --
// go-sdk's storage/** only implements UHRP (hash-addressed URLs and their
// HTTP hosting API), a different, simpler protocol. Building a CHIRP
// tree/blob encoder from scratch is a new protocol implementation, which is
// out of scope for a conformance-parity fix (see gasp-protocol/air-gap-optical
// for the same class of gap).
func TestStorageCHIRP(t *testing.T) {
	f := conformance.Load(t, "storage/chirp-v1.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		conformance.GoGap(t, "go-sdk has no CHIRP implementation (no @bsv/chirp port); "+
			"storage/** only implements UHRP, a different content-addressing protocol")
	})
}
