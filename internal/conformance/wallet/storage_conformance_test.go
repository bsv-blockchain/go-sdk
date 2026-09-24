package wallet_test

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
)

// TestStorageAdapterConformance runs wallet/storage/adapter-conformance.json.
// These vectors exercise a wallet-toolbox storage HTTP API (GET/POST
// /storage/v1/... routes over TableSettings, TableUser, etc.) — a whole
// server-side storage-provider protocol that has no implementation anywhere
// in go-sdk (no HTTP storage routes, no TableSettings/TableUser schema, no
// SQLite-backed WalletStorageManager equivalent). This is a wholesale missing
// feature, not a behavioral mismatch in existing code.
func TestStorageAdapterConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/storage/adapter-conformance.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		conformance.GoGap(t, "go-sdk has no wallet-toolbox-equivalent storage HTTP API (no /storage/v1 routes, no TableSettings/TableUser schema, no storage provider implementation at all)")
	})
}

// TestStorageSyncTransferConformance runs
// wallet/storage/sync-transfer.json. These vectors exercise wallet-toolbox's
// binary sync-transfer wire framing (a length-prefixed JSON header with a
// "$bsvBinary" extension for raw byte fields, SHA-256-covered). go-sdk has no
// storage-sync implementation and no such framing/encoding anywhere in the
// codebase.
func TestStorageSyncTransferConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/storage/sync-transfer.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		conformance.GoGap(t, "go-sdk has no wallet-toolbox-equivalent storage-sync implementation or its $bsvBinary length-prefixed frame encoding")
	})
}
