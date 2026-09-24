// Package sync_test runs the ts-stack sync/* conformance vectors against
// go-sdk. None of BRC-136 BASM, the wallet-toolbox BRC-40 sync-chunk
// protocol, the chaintracks-v2 HTTP API, or the BRC-21 GASP protocol have a
// Go implementation anywhere in this repository, so every vector here is a
// declared GoGap rather than a behavioral test. See each Test function for
// the specific reason.
package sync_test

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
)

// TestSyncBRC136BASM: go-sdk has no BRC-136 BASM implementation. The
// reference (packages/overlays/overlay/src/BASM.ts) computes a
// display-order/internal-byte-order Merkle-style root over txids plus a
// TAC (Topic Anchor Chain) hash, and exposes HTTP routes
// (/requestTopicAnchorTip) that only overlay-express implements. There is no
// equivalent root/TAC/HTTP surface under overlay/**, sync-related code, or
// elsewhere in go-sdk; building it from scratch is a new protocol
// implementation, out of scope for a conformance-parity fix.
func TestSyncBRC136BASM(t *testing.T) {
	f := conformance.Load(t, "sync/brc136-basm.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		conformance.GoGap(t, "go-sdk has no BRC-136 BASM implementation (root/TAC computation or "+
			"HTTP routes); no equivalent exists in overlay/** or elsewhere in this repo")
	})
}

// TestSyncBRC40UserState: the vector file's parity_class is "intended"
// (a Go-SDK-scope decision already recorded in the corpus), so
// conformance.Run governed-skips every vector automatically -- this test
// only proves the file loads and each vector is reachable. Reference is
// wallet-toolbox's getSyncChunk.ts, a server-side storage sync protocol that
// go-sdk (a client SDK) does not implement.
func TestSyncBRC40UserState(t *testing.T) {
	f := conformance.Load(t, "sync/brc40-user-state.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		t.Fatalf("vector %s ran instead of being governed-skipped; brc40-user-state.json's "+
			"file-level parity_class should be \"intended\"", v.ID)
	})
}

// TestSyncChaintracksV2HTTP: go-sdk has no client for the chaintracks-server
// v2 HTTP API (reference_impl: chaintracks-server@1.0.2). The only chain
// tracker in this repo is transaction/chaintracker (WhatsOnChain-backed),
// which implements a different interface and is owned by sdk-transactions,
// not this domain. There is no chaintracks-v2 client to exercise.
func TestSyncChaintracksV2HTTP(t *testing.T) {
	f := conformance.Load(t, "sync/chaintracks-v2-http.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		conformance.GoGap(t, "go-sdk has no chaintracks-v2 HTTP client; transaction/chaintracker "+
			"implements a different chain-tracker protocol (WhatsOnChain) and is owned elsewhere")
	})
}

// TestSyncGASPProtocol: go-sdk has no GASP (Graph Aware Sync Protocol,
// BRC-21) implementation. The reference lives in a standalone
// packages/gasp-core module with no Go port anywhere in this repository.
// Building it from scratch is a new protocol implementation, out of scope
// for a conformance-parity fix.
func TestSyncGASPProtocol(t *testing.T) {
	f := conformance.Load(t, "sync/gasp-protocol.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		conformance.GoGap(t, "go-sdk has no GASP (BRC-21) implementation; packages/gasp-core has "+
			"no Go port anywhere in this repository")
	})
}
