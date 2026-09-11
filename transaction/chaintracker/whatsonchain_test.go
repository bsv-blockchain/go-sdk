// whatsonchain_test.go

package chaintracker

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	woc "github.com/mrz1836/go-whatsonchain"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
)

// mockHTTPClient is a socket-free util.HTTPClient (and go-whatsonchain
// HTTPInterface) for the chaintracker tests. It builds the canned response inside
// Do (rather than accepting a response-producing closure) so no *http.Response is
// constructed at a call site the bodyclose linter watches. It lives in the test
// package rather than reusing util/test_util because transaction imports
// chaintracker, so a white-box chaintracker test cannot import util/test_util
// without an import cycle.
type mockHTTPClient struct {
	status int
	body   string
	err    error
}

// Do returns the mock's canned error, or a response built from status and body.
func (m *mockHTTPClient) Do(_ *http.Request) (*http.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &http.Response{
		StatusCode: m.status,
		Status:     http.StatusText(m.status),
		Body:       io.NopCloser(strings.NewReader(m.body)),
		Header:     make(http.Header),
	}, nil
}

// mustJSON JSON-encodes v, failing the test if encoding fails.
func mustJSON(t testing.TB, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

// jsonClient returns a mock answering every request with a 200 JSON encoding of v.
func jsonClient(t testing.TB, v any) *mockHTTPClient {
	return &mockHTTPClient{status: http.StatusOK, body: mustJSON(t, v)}
}

// statusClient returns a mock answering every request with the given status/body.
func statusClient(status int, body string) *mockHTTPClient {
	return &mockHTTPClient{status: status, body: body}
}

// newTestWOC builds a WhatsOnChain wired to an injected mock HTTP client, so tests
// never touch the network.
func newTestWOC(mock *mockHTTPClient) *WhatsOnChain {
	return NewWhatsOnChain(MainNet, "testapikey", WithHTTPClient(mock))
}

func TestWhatsOnChainGetBlockHeaderSuccess(t *testing.T) {
	t.Parallel()

	hash := chainhash.HashH([]byte("block hash"))
	merkleRoot := chainhash.HashH([]byte("merkle root"))
	prevHash := chainhash.HashH([]byte("prev hash"))

	info := woc.BlockInfo{
		Hash:              hash.String(),
		Height:            100,
		Version:           1,
		MerkleRoot:        merkleRoot.String(),
		Time:              1234567890,
		Nonce:             42,
		Bits:              "1d00ffff",
		PreviousBlockHash: prevHash.String(),
	}

	wc := newTestWOC(jsonClient(t, info))

	header, err := wc.GetBlockHeader(t.Context(), 100)
	require.NoError(t, err)
	require.NotNil(t, header)
	require.Equal(t, uint32(100), header.Height)
	require.Equal(t, uint32(1), header.Version)
	require.Equal(t, uint32(1234567890), header.Time)
	require.Equal(t, uint32(42), header.Nonce)
	require.Equal(t, "1d00ffff", header.Bits)
	require.True(t, header.Hash.IsEqual(&hash))
	require.True(t, header.MerkleRoot.IsEqual(&merkleRoot))
	require.True(t, header.PrevHash.IsEqual(&prevHash))
}

func TestWhatsOnChainGetBlockHeaderEmptyPrevHash(t *testing.T) {
	t.Parallel()

	// A genesis-style block reports an empty previousblockhash, which maps to a nil
	// PrevHash rather than a parse error.
	merkleRoot := chainhash.HashH([]byte("merkle root"))
	info := woc.BlockInfo{
		Hash:              chainhash.HashH([]byte("hash")).String(),
		Height:            0,
		MerkleRoot:        merkleRoot.String(),
		PreviousBlockHash: "",
	}

	wc := newTestWOC(jsonClient(t, info))

	header, err := wc.GetBlockHeader(t.Context(), 0)
	require.NoError(t, err)
	require.NotNil(t, header)
	require.Nil(t, header.PrevHash)
}

func TestWhatsOnChainGetBlockHeaderNotFound(t *testing.T) {
	t.Parallel()

	// A 404 with an empty body maps to go-whatsonchain's ErrBlockNotFound, which
	// GetBlockHeader translates to (nil, nil).
	wc := newTestWOC(statusClient(http.StatusNotFound, ""))

	header, err := wc.GetBlockHeader(t.Context(), 100)
	require.NoError(t, err)
	require.Nil(t, header)
}

func TestWhatsOnChainGetBlockHeaderErrorResponse(t *testing.T) {
	t.Parallel()

	wc := newTestWOC(statusClient(http.StatusInternalServerError, "Internal Server Error"))

	header, err := wc.GetBlockHeader(t.Context(), 100)
	require.Error(t, err)
	require.Nil(t, header)
}

func TestWhatsOnChainIsValidRootForHeightSuccess(t *testing.T) {
	t.Parallel()

	merkleRoot := chainhash.HashH([]byte("test merkle root"))
	info := woc.BlockInfo{
		Hash:       chainhash.HashH([]byte("hash")).String(),
		MerkleRoot: merkleRoot.String(),
	}

	wc := newTestWOC(jsonClient(t, info))

	isValid, err := wc.IsValidRootForHeight(t.Context(), &merkleRoot, 100)
	require.NoError(t, err)
	require.True(t, isValid)
}

func TestWhatsOnChainIsValidRootForHeightInvalidRoot(t *testing.T) {
	t.Parallel()

	merkleRoot := chainhash.HashH([]byte("test merkle root"))
	differentMerkleRoot := chainhash.HashH([]byte("different merkle root"))
	info := woc.BlockInfo{
		Hash:       chainhash.HashH([]byte("hash")).String(),
		MerkleRoot: merkleRoot.String(),
	}

	wc := newTestWOC(jsonClient(t, info))

	isValid, err := wc.IsValidRootForHeight(t.Context(), &differentMerkleRoot, 100)
	require.NoError(t, err)
	require.False(t, isValid)
}

func TestWhatsOnChainCurrentHeight(t *testing.T) {
	t.Parallel()

	wc := newTestWOC(jsonClient(t, woc.ChainInfo{Blocks: 800000}))

	height, err := wc.CurrentHeight(t.Context())
	require.NoError(t, err)
	require.Equal(t, uint32(800000), height)
}
