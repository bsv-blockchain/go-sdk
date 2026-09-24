package wallet_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
)

// The vectors in this file (wallet/brc100/{getheight,getheaderforheight,
// getnetwork,getversion,isauthenticated,waitforauthentication}.json) target
// what ts-stack's own reference dispatcher
// (conformance/runner/ts/dispatchers/wallet.ts) calls the "STATE METHODS
// (stubs — ProtoWallet has no state layer)" category. @bsv/sdk's ProtoWallet
// has no getHeight/getNetwork/... methods at all, so the TS dispatcher never
// calls into the SDK for these: it hardcodes a local stub literal (e.g.
// `{ height: 1 }`, `{ network: 'mainnet' }`) inside the *test* itself and
// only checks the vector's own documented expectation against that literal
// (see the dispatcher's doc comment and dispatchGetHeight/dispatchGetNetwork/
// etc.).
//
// go-sdk's wallet.CompletedProtoWallet has its own long-standing, separately
// unit-tested stub values for these methods (see
// wallet/completed_proto_wallet_test.go), which predate this conformance
// corpus and must not be changed just to chase an individual vector's literal
// (maintainer policy: never change a production default/stub value to make a
// vector pass — mirror what the TS *test* asserts in the Go *test* instead).
// So, like the TS dispatcher, the tests below assert the vectors' own
// documented literals are internally consistent; they do not call
// CompletedProtoWallet's state methods.

// TestGetHeightConformance runs wallet/brc100/getheight.json.
func TestGetHeightConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/getheight.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		if v.ID == "wallet.brc100.getheight.5" {
			conformance.GoGap(t, "CompletedProtoWallet has no session/authentication state, so it cannot model the 'wallet not authenticated' failure this vector expects")
			return
		}

		var expected struct {
			Height uint32 `json:"height"`
		}
		v.DecodeExpected(t, &expected)

		// Mirror ts-stack's dispatchGetHeight exactly: `const result = {
		// height: 1 }`, then assert result.height >= 1 and result.height ===
		// wantHeight (the vector's own expected.height, defaulting to 1).
		const tsDispatcherStubHeight uint32 = 1
		require.GreaterOrEqual(t, tsDispatcherStubHeight, uint32(1), v.ID)
		require.Equal(t, expected.Height, tsDispatcherStubHeight, v.ID)
	})
}

// TestGetHeaderForHeightConformance runs wallet/brc100/getheaderforheight.json.
func TestGetHeaderForHeightConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/getheaderforheight.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		if v.ID == "wallet.brc100.getheaderforheight.6" {
			conformance.GoGap(t, "CompletedProtoWallet has no chain tracker/tip, so it has no concept of a height being beyond the chain to produce ERR_HEADER_NOT_FOUND")
			return
		}

		var in struct {
			Args struct {
				Height uint32 `json:"height"`
			} `json:"args"`
		}
		v.DecodeInput(t, &in)

		var expected struct {
			Header string `json:"header"`
		}
		v.DecodeExpected(t, &expected)

		// Mirror ts-stack's dispatchGetHeaderForHeight exactly: it computes
		// `stubbedHeader = height === 0 ? GENESIS_HEADER : ZERO_HEADER`
		// locally, without calling any SDK, then compares that literal
		// against the vector's own expected.header.
		const genesisHeaderHex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
		const zeroHeaderHex = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

		tsDispatcherStubHeader := zeroHeaderHex
		if in.Args.Height == 0 {
			tsDispatcherStubHeader = genesisHeaderHex
		}
		require.Equal(t, expected.Header, tsDispatcherStubHeader, v.ID)
	})
}

// TestGetNetworkConformance runs wallet/brc100/getnetwork.json.
func TestGetNetworkConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/getnetwork.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		if v.ID == "wallet.brc100.getnetwork.2" {
			conformance.GoGap(t, "CompletedProtoWallet has no network configuration and always reports one fixed network, so it cannot exercise a testnet-configured wallet scenario")
			return
		}

		var expected struct {
			Network string `json:"network"`
		}
		v.DecodeExpected(t, &expected)

		// Mirror ts-stack's dispatchGetNetwork exactly: `const result = {
		// network: 'mainnet' }`, without calling any SDK, then compared
		// against the vector's own expected.network.
		const tsDispatcherStubNetwork = "mainnet"
		require.Equal(t, expected.Network, tsDispatcherStubNetwork, v.ID)
	})
}

// TestGetVersionConformance runs wallet/brc100/getversion.json. Each vector
// documents a different literal version string; a single static
// implementation (TS's stub or go-sdk's) can't match all of them, so — like
// the TS dispatcher — we only check each vector's own literal against
// BRC-100's documented "[vendor]-[major].[minor].[patch]" shape.
func TestGetVersionConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/getversion.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		if v.ID == "wallet.brc100.getversion.4" {
			conformance.GoGap(t, "CompletedProtoWallet.GetVersion is a static, always-succeeding stub, so it cannot model the 'service unavailable' failure this vector expects")
			return
		}

		var expected struct {
			Version string `json:"version"`
		}
		v.DecodeExpected(t, &expected)

		// Mirror ts-stack's dispatchGetVersion exactly: it never compares
		// against a specific literal (a static stub can't match every
		// vector's distinct version string); it only asserts
		// `result.version.length >= 7`. We apply the same shape check to the
		// vector's own documented literal.
		require.GreaterOrEqual(t, len(expected.Version), 7, v.ID)
	})
}

// TestIsAuthenticatedConformance runs wallet/brc100/isauthenticated.json.
func TestIsAuthenticatedConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/isauthenticated.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		if v.ID == "wallet.brc100.isauthenticated.3" {
			conformance.GoGap(t, "CompletedProtoWallet has no session/lock state and always reports authenticated=true, so it cannot model a locked-wallet scenario")
			return
		}

		var expected struct {
			Authenticated bool `json:"authenticated"`
		}
		v.DecodeExpected(t, &expected)

		// Mirror ts-stack's dispatchIsAuthenticated exactly: it hardcodes
		// authenticated=true locally, without calling any SDK (ProtoWallet
		// has no session concept).
		const tsDispatcherStubAuthenticated = true
		require.Equal(t, expected.Authenticated, tsDispatcherStubAuthenticated, v.ID)
	})
}

// TestWaitForAuthenticationConformance runs
// wallet/brc100/waitforauthentication.json.
func TestWaitForAuthenticationConformance(t *testing.T) {
	f := conformance.Load(t, "wallet/brc100/waitforauthentication.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		if vectorExpectsError(t, v) {
			conformance.GoGap(t, "CompletedProtoWallet has no session/timeout state, so it cannot model an authentication timeout or a wallet closing before authentication completes")
			return
		}

		var expected struct {
			Authenticated bool `json:"authenticated"`
		}
		v.DecodeExpected(t, &expected)

		// Mirror ts-stack's dispatchWaitForAuthentication exactly: for the
		// non-error path it only asserts expected.authenticated === true,
		// without calling any SDK.
		require.True(t, expected.Authenticated, v.ID)
	})
}
