package wallet_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// TestCreateActionConformance runs wallet/brc100/createaction.json. Every one
// of its 90 vectors requires a funded wallet (change UTXOs to pay fees), which
// needs a wallet-toolbox-style storage/UTXO harness go-sdk does not
// implement; the ts-stack reference runner demotes the same vectors to
// parity_class "intended" for the identical reason, so conformance.Run
// governed-skips them all here without this callback ever running.
func TestCreateActionConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/createaction.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		t.Fatalf("%s: unexpectedly reached — createAction vectors require a funded-wallet storage harness go-sdk doesn't have; if this now runs, the corpus's governed skip changed and this test needs real assertions", v.ID)
	})
}

// TestSignActionConformance runs wallet/brc100/signaction.json. All 8 vectors
// reference in-flight actions that only exist inside a stateful, storage-backed
// wallet; go-sdk has no such implementation, matching the ts-stack reference
// runner's own "intended" demotion of the same vectors.
func TestSignActionConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/signaction.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		t.Fatalf("%s: unexpectedly reached — signAction vectors require in-flight actions from a stateful storage harness go-sdk doesn't have; if this now runs, the corpus's governed skip changed and this test needs real assertions", v.ID)
	})
}

// TestAbortActionConformance runs wallet/brc100/abortaction.json. The 6
// success-path vectors need a pre-existing in-flight action or broadcast tx
// and are governed-skipped (parity_class intended). The 2 remaining vectors
// expect an error from a fresh wallet, but CompletedProtoWallet.AbortAction is
// a documented nil,nil stub with no storage layer to detect an unknown or
// empty action reference, so go-sdk has no way to produce that error either.
func TestAbortActionConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/abortaction.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		conformance.GoGap(t, "CompletedProtoWallet.AbortAction is a documented nil,nil stub; go-sdk has no storage layer to detect an unknown or empty action reference")
	})
}

// TestRelinquishOutputConformance runs wallet/brc100/relinquishoutput.json.
// See TestAbortActionConformance: the success vectors need a pre-existing
// output and are governed-skipped; the 2 error vectors need a storage layer
// go-sdk's CompletedProtoWallet.RelinquishOutput stub doesn't have.
func TestRelinquishOutputConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/relinquishoutput.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		conformance.GoGap(t, "CompletedProtoWallet.RelinquishOutput is a documented nil,nil stub; go-sdk has no storage layer to detect an unknown output")
	})
}

// TestAcquireCertificateConformance runs
// wallet/brc100/acquirecertificate.json. The success vectors are
// governed-skipped (synthetic/placeholder signatures, or a live certifier
// URL); the 3 remaining vectors expect validation errors (invalid signature,
// bad certifier key, malformed revocation outpoint) that
// CompletedProtoWallet.AcquireCertificate — a documented nil,nil stub with no
// certificate verification logic — cannot produce.
func TestAcquireCertificateConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/acquirecertificate.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		conformance.GoGap(t, "CompletedProtoWallet.AcquireCertificate is a documented nil,nil stub with no certificate-signature validation logic")
	})
}

// TestProveCertificateConformance runs wallet/brc100/provecertificate.json.
// The success vectors need a pre-existing certificate and are
// governed-skipped; the 1 remaining vector expects a lookup-failure error that
// CompletedProtoWallet.ProveCertificate — a stub with no certificate storage —
// cannot produce.
func TestProveCertificateConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/provecertificate.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		conformance.GoGap(t, "CompletedProtoWallet.ProveCertificate has no certificate storage, so it cannot produce a 'no matching certificate' lookup error")
	})
}

// TestRelinquishCertificateConformance runs
// wallet/brc100/relinquishcertificate.json. The success vectors need a
// pre-existing certificate and are governed-skipped; the 2 remaining vectors
// expect a not-found error that CompletedProtoWallet.RelinquishCertificate — a
// documented nil,nil stub — cannot produce.
func TestRelinquishCertificateConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/relinquishcertificate.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		conformance.GoGap(t, "CompletedProtoWallet.RelinquishCertificate is a documented nil,nil stub; go-sdk has no storage layer to detect an unknown certificate")
	})
}

// TestInternalizeActionConformance runs
// wallet/brc100/internalizeaction.json. The success vectors carry placeholder
// (non-BEEF) tx bytes and are governed-skipped; the 2 remaining vectors expect
// a BEEF-validation error that CompletedProtoWallet.InternalizeAction — a
// documented nil,nil stub with no BEEF parsing — cannot produce.
func TestInternalizeActionConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/internalizeaction.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		conformance.GoGap(t, "CompletedProtoWallet.InternalizeAction is a documented nil,nil stub with no BEEF validation logic")
	})
}

// TestListActionsConformance runs wallet/brc100/listactions.json.
// CompletedProtoWallet.ListActions is a documented nil,nil "not implemented"
// stub (see completed_proto_wallet_test.go). ts-stack's own dispatcher
// (dispatchListActions in dispatchers/wallet.ts) never exercises ProtoWallet
// for this category either — every vector is run against a separate, real
// @wallet-toolbox Wallet backed by an in-memory storage harness
// (setupTestWallet), which go-sdk's ProtoWallet-based CompletedProtoWallet has
// no equivalent of at all (no storage layer, no listActions implementation).
func TestListActionsConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/listactions.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		conformance.GoGap(t, "CompletedProtoWallet.ListActions is a documented nil,nil stub; ts-stack's dispatchListActions runs every vector against a separate, real @wallet-toolbox Wallet + in-memory storage harness go-sdk's CompletedProtoWallet has no equivalent of")
	})
}

// TestListOutputsConformance runs wallet/brc100/listoutputs.json. See
// TestListActionsConformance: CompletedProtoWallet.ListOutputs is likewise a
// documented nil,nil stub, and ts-stack's dispatchListOutputs likewise drives
// a real @wallet-toolbox Wallet + storage harness go-sdk has no equivalent of.
func TestListOutputsConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/listoutputs.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		conformance.GoGap(t, "CompletedProtoWallet.ListOutputs is a documented nil,nil stub; ts-stack's dispatchListOutputs runs every vector against a separate, real @wallet-toolbox Wallet + in-memory storage harness go-sdk's CompletedProtoWallet has no equivalent of")
	})
}

// TestListCertificatesConformance runs
// wallet/brc100/listcertificates.json against
// CompletedProtoWallet.ListCertificates.
func TestListCertificatesConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/listcertificates.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		in := decodeVectorInput(t, v)
		w := newCompletedWallet(t, in.RootKey)

		var args wallet.ListCertificatesArgs
		require.NoError(t, json.Unmarshal(in.Args, &args), v.ID)

		result, err := w.ListCertificates(context.Background(), args, in.Originator)
		require.NoError(t, err, v.ID)

		var expected wallet.ListCertificatesResult
		v.DecodeExpected(t, &expected)
		require.Equal(t, expected.TotalCertificates, result.TotalCertificates, v.ID)
		require.Equal(t, expected.Certificates, result.Certificates, v.ID)
	})
}

// TestDiscoverByIdentityKeyConformance runs
// wallet/brc100/discoverbyidentitykey.json. See TestListActionsConformance:
// CompletedProtoWallet.DiscoverByIdentityKey is a documented nil,nil stub, and
// ts-stack's dispatchDiscoverByIdentityKey drives a real @wallet-toolbox
// Wallet (with a stub LookupResolver) go-sdk has no equivalent of.
func TestDiscoverByIdentityKeyConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/discoverbyidentitykey.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		conformance.GoGap(t, "CompletedProtoWallet.DiscoverByIdentityKey is a documented nil,nil stub; ts-stack's dispatchDiscoverByIdentityKey runs every vector against a separate, real @wallet-toolbox Wallet (with a stub LookupResolver) go-sdk's CompletedProtoWallet has no equivalent of")
	})
}

// TestDiscoverByAttributesConformance runs
// wallet/brc100/discoverbyattributes.json. See
// TestDiscoverByIdentityKeyConformance.
func TestDiscoverByAttributesConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/discoverbyattributes.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		conformance.GoGap(t, "CompletedProtoWallet.DiscoverByAttributes is a documented nil,nil stub; ts-stack's dispatchDiscoverByAttributes runs every vector against a separate, real @wallet-toolbox Wallet (with a stub LookupResolver) go-sdk's CompletedProtoWallet has no equivalent of")
	})
}
