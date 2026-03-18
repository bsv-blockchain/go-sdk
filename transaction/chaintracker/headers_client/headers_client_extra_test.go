package headers_client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/stretchr/testify/require"
)

const (
	testAPIKey  = "test-key"
	notJSONBody = "not json"
)

func TestGetHTTPClientWithCustomClient(t *testing.T) {
	customClient := &http.Client{}
	c := &Client{
		Url:        "http://example.com",
		ApiKey:     testAPIKey,
		httpClient: customClient,
	}
	got := c.getHTTPClient()
	require.Equal(t, customClient, got)
}

func TestGetHTTPClientWithNilClient(t *testing.T) {
	c := &Client{
		Url:    "http://example.com",
		ApiKey: testAPIKey,
	}
	got := c.getHTTPClient()
	require.NotNil(t, got)
}

func TestIsValidRootForHeightConfirmed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/chain/merkleroot/verify", r.URL.Path)
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))
		require.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))

		w.WriteHeader(http.StatusOK)
		resp := struct {
			ConfirmationState string `json:"confirmationState"`
		}{ConfirmationState: "CONFIRMED"}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	// IsValidRootForHeight uses its own http.Client{} internally (not c.httpClient)
	// so we need to use a real server but point to ts.URL
	mockHash, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	c := Client{
		Url:    ts.URL,
		ApiKey: testAPIKey,
	}
	valid, err := c.IsValidRootForHeight(context.Background(), mockHash, 100)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestIsValidRootForHeightNotConfirmed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		resp := struct {
			ConfirmationState string `json:"confirmationState"`
		}{ConfirmationState: "UNCONFIRMED"}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	mockHash, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	c := Client{
		Url:    ts.URL,
		ApiKey: testAPIKey,
	}
	valid, err := c.IsValidRootForHeight(context.Background(), mockHash, 100)
	require.NoError(t, err)
	require.False(t, valid)
}

func TestIsValidRootForHeightInvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(notJSONBody))
	}))
	defer ts.Close()

	mockHash, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	c := Client{
		Url:    ts.URL,
		ApiKey: testAPIKey,
	}
	_, err := c.IsValidRootForHeight(context.Background(), mockHash, 100)
	require.Error(t, err)
	require.Contains(t, err.Error(), "error unmarshaling JSON")
}

func TestBlockByHeightLongestChain(t *testing.T) {
	mockHashHex := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/chain/header/byHeight" {
			// Return a JSON array of headers using raw JSON to avoid chainhash marshaling issues
			_, _ = fmt.Fprintf(w, `[{"height":0,"hash":%q,"version":1,"merkleRoot":%q,"creationTimestamp":0,"difficultyTarget":0,"nonce":0,"prevBlockHash":%q}]`,
				mockHashHex, mockHashHex, mockHashHex)
		} else {
			// GetBlockState call
			_, _ = fmt.Fprintf(w, `{"state":"LONGEST_CHAIN","height":100,"header":{"height":0,"hash":%q,"version":1,"merkleRoot":%q,"creationTimestamp":0,"difficultyTarget":0,"nonce":0,"prevBlockHash":%q}}`,
				mockHashHex, mockHashHex, mockHashHex)
		}
	}))
	defer ts.Close()

	c := &Client{
		Url:    ts.URL,
		ApiKey: testAPIKey,
	}

	header, err := c.BlockByHeight(context.Background(), 100)
	require.NoError(t, err)
	require.NotNil(t, header)
	require.Equal(t, uint32(100), header.Height)
}

func TestBlockByHeightNoLongestChainFallback(t *testing.T) {
	mockHashHex := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/chain/header/byHeight" {
			_, _ = fmt.Fprintf(w, `[{"height":0,"hash":%q,"version":1,"merkleRoot":%q,"creationTimestamp":0,"difficultyTarget":0,"nonce":0,"prevBlockHash":%q}]`,
				mockHashHex, mockHashHex, mockHashHex)
		} else {
			_, _ = fmt.Fprintf(w, `{"state":"STALE","height":100,"header":{"height":0,"hash":%q,"version":1,"merkleRoot":%q,"creationTimestamp":0,"difficultyTarget":0,"nonce":0,"prevBlockHash":%q}}`,
				mockHashHex, mockHashHex, mockHashHex)
		}
	}))
	defer ts.Close()

	c := &Client{
		Url:    ts.URL,
		ApiKey: testAPIKey,
	}

	header, err := c.BlockByHeight(context.Background(), 100)
	require.NoError(t, err)
	require.NotNil(t, header)
	require.Equal(t, uint32(100), header.Height)
}

func TestBlockByHeightEmpty(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]Header{})
	}))
	defer ts.Close()

	c := &Client{
		Url:    ts.URL,
		ApiKey: testAPIKey,
	}

	_, err := c.BlockByHeight(context.Background(), 100)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no block headers found")
}

func TestBlockByHeightDecodeError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(notJSONBody))
	}))
	defer ts.Close()

	c := &Client{
		Url:    ts.URL,
		ApiKey: testAPIKey,
	}

	_, err := c.BlockByHeight(context.Background(), 100)
	require.Error(t, err)
}

func TestGetBlockState(t *testing.T) {
	mockHashHex := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Contains(t, r.URL.Path, "/api/v1/chain/header/state/")
		_, _ = fmt.Fprintf(w, `{"state":"LONGEST_CHAIN","height":100,"header":{"height":0,"hash":%q,"version":1,"merkleRoot":%q,"creationTimestamp":0,"difficultyTarget":0,"nonce":0,"prevBlockHash":%q}}`,
			mockHashHex, mockHashHex, mockHashHex)
	}))
	defer ts.Close()

	c := &Client{
		Url:    ts.URL,
		ApiKey: testAPIKey,
	}

	state, err := c.GetBlockState(context.Background(), mockHashHex)
	require.NoError(t, err)
	require.NotNil(t, state)
	require.Equal(t, "LONGEST_CHAIN", state.State)
}

func TestGetBlockStateDecodeError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(notJSONBody))
	}))
	defer ts.Close()

	c := &Client{
		Url:    ts.URL,
		ApiKey: testAPIKey,
	}

	_, err := c.GetBlockState(context.Background(), "somehash")
	require.Error(t, err)
}

func TestGetChaintip(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/api/v1/chain/tip/longest", r.URL.Path)
		require.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))
		// State has nested Header with chainhash fields; send raw JSON
		_, _ = w.Write([]byte(`{"state":"LONGEST_CHAIN","height":800000,"header":{"height":0,"hash":"0000000000000000000000000000000000000000000000000000000000000000","version":0,"merkleRoot":"0000000000000000000000000000000000000000000000000000000000000000","creationTimestamp":0,"difficultyTarget":0,"nonce":0,"prevBlockHash":"0000000000000000000000000000000000000000000000000000000000000000"}}`))
	}))
	defer ts.Close()

	c := &Client{
		Url:        ts.URL,
		ApiKey:     testAPIKey,
		httpClient: ts.Client(),
	}

	state, err := c.GetChaintip(context.Background())
	require.NoError(t, err)
	require.NotNil(t, state)
	require.Equal(t, uint32(800000), state.Height)
}

func TestGetChaintipDecodeError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(notJSONBody))
	}))
	defer ts.Close()

	c := &Client{
		Url:        ts.URL,
		ApiKey:     testAPIKey,
		httpClient: ts.Client(),
	}

	_, err := c.GetChaintip(context.Background())
	require.Error(t, err)
}

func TestCurrentHeight(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"state":"LONGEST_CHAIN","height":850000,"header":{"height":0,"hash":"0000000000000000000000000000000000000000000000000000000000000000","version":0,"merkleRoot":"0000000000000000000000000000000000000000000000000000000000000000","creationTimestamp":0,"difficultyTarget":0,"nonce":0,"prevBlockHash":"0000000000000000000000000000000000000000000000000000000000000000"}}`))
	}))
	defer ts.Close()

	c := &Client{
		Url:        ts.URL,
		ApiKey:     testAPIKey,
		httpClient: ts.Client(),
	}

	height, err := c.CurrentHeight(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint32(850000), height)
}

func TestCurrentHeightError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(notJSONBody))
	}))
	defer ts.Close()

	c := &Client{
		Url:        ts.URL,
		ApiKey:     testAPIKey,
		httpClient: ts.Client(),
	}

	height, err := c.CurrentHeight(context.Background())
	require.Error(t, err)
	require.Equal(t, uint32(0), height)
}
