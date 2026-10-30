package substrates_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/substrates"
)

// The fixture is ts-stack's frozen SDK 3.2.1 request/response vectors, copied
// verbatim from
// packages/sdk/src/wallet/substrates/__tests/fixtures/listOutputs-sdk-3.2.1.json.
// It pins the legacy listOutputs wire that every deployed peer speaks, so both
// SDKs are checked against the same bytes. The negotiated "spendable" layout is
// ts-stack-main-only (unreleased), so it is exercised end to end through the Go
// processor and transceiver rather than against a frozen vector.
const listOutputsFixtureFile = "listOutputs-sdk-3.2.1.json"

type loFixtureFile struct {
	Cases []loFixtureCase `json:"cases"`
}

type loFixtureCase struct {
	Name        string          `json:"name"`
	Args        loFixtureArgs   `json:"args"`
	Originator  string          `json:"originator"`
	Result      loFixtureResult `json:"result"`
	RequestHex  string          `json:"requestHex"`
	ResponseHex string          `json:"responseHex"`
}

type loFixtureArgs struct {
	Basket                    string   `json:"basket"`
	Tags                      []string `json:"tags"`
	TagQueryMode              string   `json:"tagQueryMode"`
	Include                   string   `json:"include"`
	IncludeCustomInstructions *bool    `json:"includeCustomInstructions"`
	IncludeTags               *bool    `json:"includeTags"`
	IncludeLabels             *bool    `json:"includeLabels"`
	Limit                     *uint32  `json:"limit"`
	Offset                    *uint32  `json:"offset"`
	SeekPermission            *bool    `json:"seekPermission"`
}

type loFixtureResult struct {
	TotalOutputs uint32            `json:"totalOutputs"`
	BEEF         []int             `json:"BEEF"`
	Outputs      []loFixtureOutput `json:"outputs"`
}

type loFixtureOutput struct {
	Spendable          bool     `json:"spendable"`
	Outpoint           string   `json:"outpoint"`
	Satoshis           uint64   `json:"satoshis"`
	LockingScript      string   `json:"lockingScript"`
	CustomInstructions *string  `json:"customInstructions"`
	Tags               []string `json:"tags"`
	Labels             []string `json:"labels"`
}

func loadListOutputsFixture(t *testing.T) loFixtureFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", listOutputsFixtureFile))
	require.NoError(t, err)
	var f loFixtureFile
	require.NoError(t, json.Unmarshal(data, &f))
	require.NotEmpty(t, f.Cases)
	return f
}

func (fc loFixtureCase) args() wallet.ListOutputsArgs {
	// ts-stack always serializes the request tags as an array, defaulting an
	// absent value to an empty one (0x00 on the wire). go-sdk writes a nil slice
	// as -1 and an empty slice as 0x00, so the canonical args carry an empty
	// (non-nil) tags slice to reproduce the frozen SDK 3.2.1 request bytes.
	tags := fc.Args.Tags
	if tags == nil {
		tags = []string{}
	}
	args := wallet.ListOutputsArgs{
		Basket:                    fc.Args.Basket,
		Tags:                      tags,
		IncludeCustomInstructions: fc.Args.IncludeCustomInstructions,
		IncludeTags:               fc.Args.IncludeTags,
		IncludeLabels:             fc.Args.IncludeLabels,
		Limit:                     fc.Args.Limit,
		Offset:                    fc.Args.Offset,
		SeekPermission:            fc.Args.SeekPermission,
	}
	switch fc.Args.TagQueryMode {
	case "all":
		args.TagQueryMode = wallet.QueryModeAll
	case "any":
		args.TagQueryMode = wallet.QueryModeAny
	}
	switch fc.Args.Include {
	case "locking scripts":
		args.Include = wallet.OutputIncludeLockingScripts
	case "entire transactions":
		args.Include = wallet.OutputIncludeEntireTransactions
	}
	return args
}

func (fc loFixtureCase) result(t *testing.T) wallet.ListOutputsResult {
	t.Helper()
	res := wallet.ListOutputsResult{TotalOutputs: fc.Result.TotalOutputs}
	if fc.Result.BEEF != nil {
		beef := make([]byte, len(fc.Result.BEEF))
		for i, b := range fc.Result.BEEF {
			beef[i] = byte(b) //nolint:gosec // G115 -- BEEF fixture elements are bytes (0-255)
		}
		res.BEEF = beef
	}
	res.Outputs = make([]wallet.Output, 0, len(fc.Result.Outputs))
	for _, fo := range fc.Result.Outputs {
		out := wallet.Output{
			Satoshis:  fo.Satoshis,
			Spendable: fo.Spendable,
			Tags:      fo.Tags,
			Labels:    fo.Labels,
			Outpoint:  *tu.OutpointFromString(t, fo.Outpoint),
		}
		if fo.LockingScript != "" {
			b, err := hex.DecodeString(fo.LockingScript)
			require.NoError(t, err)
			out.LockingScript = b
		}
		if fo.CustomInstructions != nil {
			out.CustomInstructions = *fo.CustomInstructions
		}
		res.Outputs = append(res.Outputs, out)
	}
	return res
}

// goCannotReproduceBytes reports whether Go's serializer cannot reproduce the
// frozen response bytes exactly. wallet.Output.CustomInstructions is a plain
// string, so Go writes a present-but-empty customInstructions ("") as absent
// (-1) rather than as a zero-length string (0x00). This predates the spendable
// work; such a case is skipped for the encode direction only (as suggested in
// the PR #390 review).
func (fc loFixtureCase) goCannotReproduceBytes() bool {
	for _, fo := range fc.Result.Outputs {
		if fo.CustomInstructions != nil && *fo.CustomInstructions == "" {
			return true
		}
	}
	return false
}

// recordingWire is a WalletWire stub that asserts the request bytes and returns
// a canned response, standing in for an old (legacy-only) peer.
type recordingWire struct {
	t           *testing.T
	expectedReq []byte
	response    []byte
	calls       int
}

func (w *recordingWire) TransmitToWallet(_ context.Context, message []byte) ([]byte, error) {
	w.calls++
	require.Equal(w.t, w.expectedReq, message, "request bytes must match the frozen SDK 3.2.1 vector")
	return w.response, nil
}

// staticWire returns a fixed response regardless of the request.
type staticWire struct {
	response []byte
	calls    int
}

func (w *staticWire) TransmitToWallet(_ context.Context, _ []byte) ([]byte, error) {
	w.calls++
	return w.response, nil
}

// stubWallet implements wallet.Interface but only answers ListOutputs; every
// other method would call the nil embedded interface and panic, which these
// tests never do.
type stubWallet struct {
	wallet.Interface

	result        wallet.ListOutputsResult
	calls         int
	gotArgs       wallet.ListOutputsArgs
	gotOriginator string
}

func (s *stubWallet) ListOutputs(_ context.Context, args wallet.ListOutputsArgs, originator string) (*wallet.ListOutputsResult, error) {
	s.calls++
	s.gotArgs = args
	s.gotOriginator = originator
	r := s.result
	return &r, nil
}

// TestListOutputsLegacyWireCompatibility pins the Go transceiver and processor
// to ts-stack's frozen SDK 3.2.1 bytes in both directions: a new Go caller
// decodes an old wallet's response, and an old caller's request drives a new Go
// wallet to emit the same response bytes.
func TestListOutputsLegacyWireCompatibility(t *testing.T) {
	fixture := loadListOutputsFixture(t)
	ctx := context.Background()

	for _, fc := range fixture.Cases {
		req, err := hex.DecodeString(fc.RequestHex)
		require.NoError(t, err)
		resp, err := hex.DecodeString(fc.ResponseHex)
		require.NoError(t, err)

		t.Run("new caller reads old wallet: "+fc.Name, func(t *testing.T) {
			wire := &recordingWire{t: t, expectedReq: req, response: resp}
			caller := &substrates.WalletWireTransceiver{Wire: wire}

			got, err := caller.ListOutputs(ctx, fc.args(), fc.Originator)
			require.NoError(t, err)
			require.Equal(t, fc.result(t), *got)
			require.Equal(t, 1, wire.calls)
		})

		t.Run("old caller reads new wallet: "+fc.Name, func(t *testing.T) {
			if fc.goCannotReproduceBytes() {
				t.Skip("output with a present-but-empty customInstructions cannot be byte-reproduced; see goCannotReproduceBytes")
			}
			stub := &stubWallet{result: fc.result(t)}
			processor := substrates.NewWalletWireProcessor(stub)

			out, err := processor.TransmitToWallet(ctx, req)
			require.NoError(t, err)
			require.Equal(t, resp, out, "response bytes must match the frozen SDK 3.2.1 vector")
			require.Equal(t, 1, stub.calls)
			require.Equal(t, fc.args(), stub.gotArgs)
			require.Equal(t, fc.Originator, stub.gotOriginator)
		})
	}
}

// TestListOutputsSpendableNegotiation exercises the opt-in spendable encoding
// where the negotiation actually happens: across the processor and transceiver.
// It mirrors ts-stack's "explicit listOutputs spendability extension" tests.
func TestListOutputsSpendableNegotiation(t *testing.T) {
	fixture := loadListOutputsFixture(t)
	ctx := context.Background()
	base := fixture.Cases[0]

	// The base result with its first output made non-spendable, representable
	// only on a negotiated connection.
	nonSpendable := func() wallet.ListOutputsResult {
		r := base.result(t)
		r.Outputs[0].Spendable = false
		return r
	}

	t.Run("spendable round trip preserves a non-spendable output", func(t *testing.T) {
		stub := &stubWallet{result: nonSpendable()}
		processor := substrates.NewWalletWireProcessor(stub)
		caller := &substrates.WalletWireTransceiver{Wire: processor, ListOutputsSpendable: true}

		got, err := caller.ListOutputs(ctx, base.args(), base.Originator)
		require.NoError(t, err)
		require.Equal(t, nonSpendable(), *got)
		require.False(t, got.Outputs[0].Spendable)
		require.True(t, got.Outputs[1].Spendable)
		// The wallet sees the clean args; the opt-in byte is consumed by the
		// processor, not forwarded.
		require.Equal(t, 1, stub.calls)
		require.Equal(t, base.args(), stub.gotArgs)
	})

	t.Run("legacy caller is refused a non-spendable result", func(t *testing.T) {
		stub := &stubWallet{result: nonSpendable()}
		processor := substrates.NewWalletWireProcessor(stub)
		caller := &substrates.WalletWireTransceiver{Wire: processor} // legacy default

		_, err := caller.ListOutputs(ctx, base.args(), base.Originator)
		require.Error(t, err)
		require.Contains(t, err.Error(), "non-spendable listOutputs records require")
	})

	t.Run("spendable caller rejects a legacy response", func(t *testing.T) {
		// An old wallet (or a transport that drops the opt-in byte) answers with
		// the legacy layout, which lacks the -1 acknowledgement marker.
		legacyResp, err := hex.DecodeString(base.ResponseHex)
		require.NoError(t, err)
		caller := &substrates.WalletWireTransceiver{Wire: &staticWire{response: legacyResp}, ListOutputsSpendable: true}

		_, err = caller.ListOutputs(ctx, base.args(), base.Originator)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing listOutputs spendable encoding acknowledgement")
	})

	t.Run("unknown or trailing extension is refused before the wallet is called", func(t *testing.T) {
		legacyReq, err := hex.DecodeString(base.RequestHex)
		require.NoError(t, err)
		for _, ext := range [][]byte{{0x00}, {0x02}, {0xff}, {0x01, 0x01}} {
			t.Run(hex.EncodeToString(ext), func(t *testing.T) {
				stub := &stubWallet{result: base.result(t)}
				processor := substrates.NewWalletWireProcessor(stub)

				msg := append(append([]byte{}, legacyReq...), ext...)
				_, err := processor.TransmitToWallet(ctx, msg)
				require.Error(t, err)
				require.Equal(t, 0, stub.calls, "the wallet must not be called on a rejected extension")
			})
		}
	})
}
