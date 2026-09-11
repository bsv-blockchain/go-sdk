package chaintracker

import (
	"net/http"
	"testing"

	woc "github.com/mrz1836/go-whatsonchain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
)

func TestNewWhatsOnChain(t *testing.T) {
	t.Parallel()

	wc := NewWhatsOnChain(MainNet, "myapikey")
	require.NotNil(t, wc)
	require.Equal(t, MainNet, wc.Network)
	require.Equal(t, "myapikey", wc.ApiKey)

	wcTest := NewWhatsOnChain(TestNet, "testkey")
	require.Equal(t, TestNet, wcTest.Network)
	require.Equal(t, "testkey", wcTest.ApiKey)
}

func TestNewWhatsOnChainWithHTTPClientIsUsed(t *testing.T) {
	t.Parallel()

	// Injecting a mock proves the option is honored: the call is answered by the
	// mock rather than the network.
	wc := NewWhatsOnChain(MainNet, "key", WithHTTPClient(jsonClient(t, woc.ChainInfo{Blocks: 12345})))

	height, err := wc.CurrentHeight(t.Context())
	require.NoError(t, err)
	require.Equal(t, uint32(12345), height)
}

func TestWithHTTPClientNilPanics(t *testing.T) {
	t.Parallel()
	require.Panics(t, func() { WithHTTPClient(nil) })
}

// An invalid network makes go-whatsonchain's client construction fail, which both
// GetBlockHeader and CurrentHeight surface as an error without any network call.
func TestGetBlockHeaderClientConstructionError(t *testing.T) {
	t.Parallel()

	wc := NewWhatsOnChain(Network("not-a-network"), "")
	header, err := wc.GetBlockHeader(t.Context(), 100)
	require.Error(t, err)
	require.Nil(t, header)
}

func TestCurrentHeightClientConstructionError(t *testing.T) {
	t.Parallel()

	wc := NewWhatsOnChain(Network("not-a-network"), "")
	height, err := wc.CurrentHeight(t.Context())
	require.Error(t, err)
	require.Zero(t, height)
}

func TestIsValidRootForHeightError(t *testing.T) {
	t.Parallel()

	wc := newTestWOC(statusClient(http.StatusInternalServerError, ""))

	hash := chainhash.HashH([]byte("test"))
	valid, err := wc.IsValidRootForHeight(t.Context(), &hash, 100)
	require.Error(t, err)
	require.False(t, valid)
}

func TestIsValidRootForHeightNilHeader(t *testing.T) {
	t.Parallel()

	// When GetBlockHeader returns (nil, nil) for a missing block (404),
	// IsValidRootForHeight returns (false, nil) instead of dereferencing the nil
	// header.
	wc := newTestWOC(statusClient(http.StatusNotFound, ""))

	hash := chainhash.HashH([]byte("test"))
	valid, err := wc.IsValidRootForHeight(t.Context(), &hash, 100)
	require.NoError(t, err)
	require.False(t, valid)
}

func TestCurrentHeightNotFound(t *testing.T) {
	t.Parallel()

	// A 404 with an empty body maps to go-whatsonchain's ErrChainInfoNotFound.
	wc := newTestWOC(statusClient(http.StatusNotFound, ""))

	height, err := wc.CurrentHeight(t.Context())
	require.Error(t, err)
	require.Zero(t, height)
	require.Contains(t, err.Error(), "chain info not found")
}

func TestCurrentHeightServerError(t *testing.T) {
	t.Parallel()

	wc := newTestWOC(statusClient(http.StatusInternalServerError, ""))

	height, err := wc.CurrentHeight(t.Context())
	require.Error(t, err)
	require.Zero(t, height)
}

func TestCurrentHeightDecodeError(t *testing.T) {
	t.Parallel()

	wc := newTestWOC(statusClient(http.StatusOK, "not json"))

	height, err := wc.CurrentHeight(t.Context())
	require.Error(t, err)
	require.Zero(t, height)
}

func TestGetBlockHeaderDecodeError(t *testing.T) {
	t.Parallel()

	wc := newTestWOC(statusClient(http.StatusOK, "not json"))

	header, err := wc.GetBlockHeader(t.Context(), 100)
	require.Error(t, err)
	require.Nil(t, header)
}

func TestGetBlockHeaderClientError(t *testing.T) {
	t.Parallel()

	wc := newTestWOC(&mockHTTPClient{err: assert.AnError})

	header, err := wc.GetBlockHeader(t.Context(), 100)
	require.Error(t, err)
	require.Nil(t, header)
}

func TestGetBlockHeaderInvalidHashInResponse(t *testing.T) {
	t.Parallel()

	// A non-hex hash in the API response surfaces as a mapping error.
	wc := newTestWOC(jsonClient(t, woc.BlockInfo{
		Hash:   "not-a-valid-hex-hash",
		Height: 100,
	}))

	header, err := wc.GetBlockHeader(t.Context(), 100)
	require.Error(t, err)
	require.Nil(t, header)
}
