package headers_client

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
)

const (
	testAPIKey  = "test-key"
	notJSONBody = "not json"
)

func TestGetHTTPClientWithCustomClient(t *testing.T) {
	t.Parallel()

	customClient := &tu.MockHTTPClient{}
	c := &Client{
		Url:        "https://headers.test",
		ApiKey:     testAPIKey,
		httpClient: customClient,
	}
	require.Same(t, customClient, c.getHTTPClient())
}

func TestGetHTTPClientWithNilClient(t *testing.T) {
	t.Parallel()

	c := &Client{
		Url:    "https://headers.test",
		ApiKey: testAPIKey,
	}
	require.Same(t, http.DefaultClient, c.getHTTPClient())
}

func TestNewClientWithHTTPClient(t *testing.T) {
	t.Parallel()

	mock := &tu.MockHTTPClient{}
	c := NewClient("https://headers.test", testAPIKey, WithHTTPClient(mock))
	require.Equal(t, "https://headers.test", c.Url)
	require.Equal(t, testAPIKey, c.ApiKey)
	require.Same(t, mock, c.getHTTPClient())
}

func TestWithHTTPClientNilPanics(t *testing.T) {
	t.Parallel()
	require.Panics(t, func() { WithHTTPClient(nil) })
}

func TestIsValidRootForHeightConfirmed(t *testing.T) {
	t.Parallel()

	mock := &tu.MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, http.MethodPost, req.Method)
			assert.Equal(t, "/api/v1/chain/merkleroot/verify", req.URL.Path)
			assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
			assert.Equal(t, "Bearer test-key", req.Header.Get("Authorization"))

			resp := struct {
				ConfirmationState string `json:"confirmationState"`
			}{ConfirmationState: "CONFIRMED"}
			return tu.JSONResponse(t, http.StatusOK, resp), nil
		},
	}

	mockHash, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	c := &Client{
		Url:        "https://headers.test",
		ApiKey:     testAPIKey,
		httpClient: mock,
	}
	valid, err := c.IsValidRootForHeight(context.Background(), mockHash, 100)
	require.NoError(t, err)
	require.True(t, valid)
}

func TestIsValidRootForHeightNotConfirmed(t *testing.T) {
	t.Parallel()

	mock := &tu.MockHTTPClient{
		DoFunc: func(_ *http.Request) (*http.Response, error) {
			resp := struct {
				ConfirmationState string `json:"confirmationState"`
			}{ConfirmationState: "UNCONFIRMED"}
			return tu.JSONResponse(t, http.StatusOK, resp), nil
		},
	}

	mockHash, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	c := &Client{
		Url:        "https://headers.test",
		ApiKey:     testAPIKey,
		httpClient: mock,
	}
	valid, err := c.IsValidRootForHeight(context.Background(), mockHash, 100)
	require.NoError(t, err)
	require.False(t, valid)
}

func TestIsValidRootForHeightInvalidJSON(t *testing.T) {
	t.Parallel()

	mock := &tu.MockHTTPClient{
		DoFunc: func(_ *http.Request) (*http.Response, error) {
			return tu.StringResponse(http.StatusOK, notJSONBody), nil
		},
	}

	mockHash, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	c := &Client{
		Url:        "https://headers.test",
		ApiKey:     testAPIKey,
		httpClient: mock,
	}
	_, err := c.IsValidRootForHeight(context.Background(), mockHash, 100)
	require.Error(t, err)
	require.Contains(t, err.Error(), "error unmarshaling JSON")
}

func TestBlockByHeightLongestChain(t *testing.T) {
	t.Parallel()

	mockHashHex := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

	mock := &tu.MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/api/v1/chain/header/byHeight" {
				// Return a JSON array of headers using raw JSON to avoid chainhash marshaling issues
				body := fmt.Sprintf(`[{"height":0,"hash":%q,"version":1,"merkleRoot":%q,"creationTimestamp":0,"difficultyTarget":0,"nonce":0,"prevBlockHash":%q}]`,
					mockHashHex, mockHashHex, mockHashHex)
				return tu.StringResponse(http.StatusOK, body), nil
			}
			// GetBlockState call
			body := fmt.Sprintf(`{"state":"LONGEST_CHAIN","height":100,"header":{"height":0,"hash":%q,"version":1,"merkleRoot":%q,"creationTimestamp":0,"difficultyTarget":0,"nonce":0,"prevBlockHash":%q}}`,
				mockHashHex, mockHashHex, mockHashHex)
			return tu.StringResponse(http.StatusOK, body), nil
		},
	}

	c := &Client{
		Url:        "https://headers.test",
		ApiKey:     testAPIKey,
		httpClient: mock,
	}

	header, err := c.BlockByHeight(context.Background(), 100)
	require.NoError(t, err)
	require.NotNil(t, header)
	require.Equal(t, uint32(100), header.Height)
}

func TestBlockByHeightNoLongestChainFallback(t *testing.T) {
	t.Parallel()

	mockHashHex := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

	mock := &tu.MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/api/v1/chain/header/byHeight" {
				body := fmt.Sprintf(`[{"height":0,"hash":%q,"version":1,"merkleRoot":%q,"creationTimestamp":0,"difficultyTarget":0,"nonce":0,"prevBlockHash":%q}]`,
					mockHashHex, mockHashHex, mockHashHex)
				return tu.StringResponse(http.StatusOK, body), nil
			}
			body := fmt.Sprintf(`{"state":"STALE","height":100,"header":{"height":0,"hash":%q,"version":1,"merkleRoot":%q,"creationTimestamp":0,"difficultyTarget":0,"nonce":0,"prevBlockHash":%q}}`,
				mockHashHex, mockHashHex, mockHashHex)
			return tu.StringResponse(http.StatusOK, body), nil
		},
	}

	c := &Client{
		Url:        "https://headers.test",
		ApiKey:     testAPIKey,
		httpClient: mock,
	}

	header, err := c.BlockByHeight(context.Background(), 100)
	require.NoError(t, err)
	require.NotNil(t, header)
	require.Equal(t, uint32(100), header.Height)
}

func TestBlockByHeightEmpty(t *testing.T) {
	t.Parallel()

	mock := &tu.MockHTTPClient{
		DoFunc: func(_ *http.Request) (*http.Response, error) {
			return tu.JSONResponse(t, http.StatusOK, []Header{}), nil
		},
	}

	c := &Client{
		Url:        "https://headers.test",
		ApiKey:     testAPIKey,
		httpClient: mock,
	}

	_, err := c.BlockByHeight(context.Background(), 100)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no block headers found")
}

func TestBlockByHeightDecodeError(t *testing.T) {
	t.Parallel()

	mock := &tu.MockHTTPClient{
		DoFunc: func(_ *http.Request) (*http.Response, error) {
			return tu.StringResponse(http.StatusOK, notJSONBody), nil
		},
	}

	c := &Client{
		Url:        "https://headers.test",
		ApiKey:     testAPIKey,
		httpClient: mock,
	}

	_, err := c.BlockByHeight(context.Background(), 100)
	require.Error(t, err)
}

func TestGetBlockState(t *testing.T) {
	t.Parallel()

	mockHashHex := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

	mock := &tu.MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, http.MethodGet, req.Method)
			assert.Contains(t, req.URL.Path, "/api/v1/chain/header/state/")
			body := fmt.Sprintf(`{"state":"LONGEST_CHAIN","height":100,"header":{"height":0,"hash":%q,"version":1,"merkleRoot":%q,"creationTimestamp":0,"difficultyTarget":0,"nonce":0,"prevBlockHash":%q}}`,
				mockHashHex, mockHashHex, mockHashHex)
			return tu.StringResponse(http.StatusOK, body), nil
		},
	}

	c := &Client{
		Url:        "https://headers.test",
		ApiKey:     testAPIKey,
		httpClient: mock,
	}

	state, err := c.GetBlockState(context.Background(), mockHashHex)
	require.NoError(t, err)
	require.NotNil(t, state)
	require.Equal(t, "LONGEST_CHAIN", state.State)
}

func TestGetBlockStateDecodeError(t *testing.T) {
	t.Parallel()

	mock := &tu.MockHTTPClient{
		DoFunc: func(_ *http.Request) (*http.Response, error) {
			return tu.StringResponse(http.StatusOK, notJSONBody), nil
		},
	}

	c := &Client{
		Url:        "https://headers.test",
		ApiKey:     testAPIKey,
		httpClient: mock,
	}

	_, err := c.GetBlockState(context.Background(), "somehash")
	require.Error(t, err)
}

func TestGetChaintip(t *testing.T) {
	t.Parallel()

	mock := &tu.MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, http.MethodGet, req.Method)
			assert.Equal(t, "/api/v1/chain/tip/longest", req.URL.Path)
			assert.Equal(t, "Bearer test-key", req.Header.Get("Authorization"))
			// State has nested Header with chainhash fields; send raw JSON
			return tu.StringResponse(http.StatusOK, `{"state":"LONGEST_CHAIN","height":800000,"header":{"height":0,"hash":"0000000000000000000000000000000000000000000000000000000000000000","version":0,"merkleRoot":"0000000000000000000000000000000000000000000000000000000000000000","creationTimestamp":0,"difficultyTarget":0,"nonce":0,"prevBlockHash":"0000000000000000000000000000000000000000000000000000000000000000"}}`), nil
		},
	}

	c := &Client{
		Url:        "https://headers.test",
		ApiKey:     testAPIKey,
		httpClient: mock,
	}

	state, err := c.GetChaintip(context.Background())
	require.NoError(t, err)
	require.NotNil(t, state)
	require.Equal(t, uint32(800000), state.Height)
}

func TestGetChaintipDecodeError(t *testing.T) {
	t.Parallel()

	mock := &tu.MockHTTPClient{
		DoFunc: func(_ *http.Request) (*http.Response, error) {
			return tu.StringResponse(http.StatusOK, notJSONBody), nil
		},
	}

	c := &Client{
		Url:        "https://headers.test",
		ApiKey:     testAPIKey,
		httpClient: mock,
	}

	_, err := c.GetChaintip(context.Background())
	require.Error(t, err)
}

func TestCurrentHeight(t *testing.T) {
	t.Parallel()

	mock := &tu.MockHTTPClient{
		DoFunc: func(_ *http.Request) (*http.Response, error) {
			return tu.StringResponse(http.StatusOK, `{"state":"LONGEST_CHAIN","height":850000,"header":{"height":0,"hash":"0000000000000000000000000000000000000000000000000000000000000000","version":0,"merkleRoot":"0000000000000000000000000000000000000000000000000000000000000000","creationTimestamp":0,"difficultyTarget":0,"nonce":0,"prevBlockHash":"0000000000000000000000000000000000000000000000000000000000000000"}}`), nil
		},
	}

	c := &Client{
		Url:        "https://headers.test",
		ApiKey:     testAPIKey,
		httpClient: mock,
	}

	height, err := c.CurrentHeight(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint32(850000), height)
}

func TestCurrentHeightError(t *testing.T) {
	t.Parallel()

	mock := &tu.MockHTTPClient{
		DoFunc: func(_ *http.Request) (*http.Response, error) {
			return tu.StringResponse(http.StatusOK, notJSONBody), nil
		},
	}

	c := &Client{
		Url:        "https://headers.test",
		ApiKey:     testAPIKey,
		httpClient: mock,
	}

	height, err := c.CurrentHeight(context.Background())
	require.Error(t, err)
	require.Equal(t, uint32(0), height)
}
