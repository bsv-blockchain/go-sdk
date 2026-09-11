package headers_client

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
)

func TestGetMerkleRootsSuccess(t *testing.T) {
	t.Parallel()

	// Create mock merkle root data
	mockHash1, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
	mockHash2, _ := chainhash.NewHashFromHex("00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048")

	expectedRoots := []MerkleRootInfo{
		{
			MerkleRoot:  *mockHash1,
			BlockHeight: 100,
		},
		{
			MerkleRoot:  *mockHash2,
			BlockHeight: 101,
		},
	}

	mock := &tu.MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			// Verify request method and path
			assert.Equal(t, http.MethodGet, req.Method)
			assert.Equal(t, "/api/v1/chain/merkleroot", req.URL.Path)

			// Verify query parameters
			batchSize := req.URL.Query().Get("batchSize")
			assert.Equal(t, "10", batchSize)

			// Verify Authorization header
			auth := req.Header.Get("Authorization")
			assert.Equal(t, "Bearer test-api-key", auth)

			// Write mock response
			response := struct {
				Content []MerkleRootInfo `json:"content"`
				Page    struct {
					LastEvaluatedKey string `json:"lastEvaluatedKey"`
				} `json:"page"`
			}{
				Content: expectedRoots,
			}
			return tu.JSONResponse(t, http.StatusOK, response), nil
		},
	}

	client := &Client{
		Url:        "https://headers.test",
		ApiKey:     "test-api-key",
		httpClient: mock,
	}

	ctx := context.Background()
	roots, err := client.GetMerkleRoots(ctx, 10, nil)
	require.NoError(t, err)
	require.Len(t, roots, 2)
	require.Equal(t, expectedRoots[0].MerkleRoot, roots[0].MerkleRoot)
	require.Equal(t, expectedRoots[0].BlockHeight, roots[0].BlockHeight)
}

func TestGetMerkleRootsWithLastEvaluatedKey(t *testing.T) {
	t.Parallel()

	lastKey, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")

	mock := &tu.MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			// Verify lastEvaluatedKey is included
			lastEvalKey := req.URL.Query().Get("lastEvaluatedKey")
			assert.Equal(t, lastKey.String(), lastEvalKey)

			response := struct {
				Content []MerkleRootInfo `json:"content"`
				Page    struct {
					LastEvaluatedKey string `json:"lastEvaluatedKey"`
				} `json:"page"`
			}{
				Content: []MerkleRootInfo{},
			}
			return tu.JSONResponse(t, http.StatusOK, response), nil
		},
	}

	client := &Client{
		Url:        "https://headers.test",
		ApiKey:     "test-api-key",
		httpClient: mock,
	}

	ctx := context.Background()
	_, err := client.GetMerkleRoots(ctx, 10, lastKey)
	require.NoError(t, err)
}

func TestGetMerkleRootsError(t *testing.T) {
	t.Parallel()

	mock := &tu.MockHTTPClient{
		DoFunc: func(_ *http.Request) (*http.Response, error) {
			return tu.StringResponse(http.StatusInternalServerError, "Internal Server Error"), nil
		},
	}

	client := &Client{
		Url:        "https://headers.test",
		ApiKey:     "test-api-key",
		httpClient: mock,
	}

	ctx := context.Background()
	_, err := client.GetMerkleRoots(ctx, 10, nil)
	require.Error(t, err)
}

func TestRegisterWebhookSuccess(t *testing.T) {
	t.Parallel()

	expectedWebhook := Webhook{
		URL:               "https://example.com/webhook",
		CreatedAt:         "2025-09-19T22:27:00Z",
		LastEmitStatus:    "success",
		LastEmitTimestamp: "2025-09-19T23:00:00Z",
		ErrorsCount:       0,
		Active:            true,
	}

	mock := &tu.MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			// Verify request method and path
			assert.Equal(t, http.MethodPost, req.Method)
			assert.Equal(t, "/api/v1/webhook", req.URL.Path)

			// Verify headers
			assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
			assert.Equal(t, "Bearer test-api-key", req.Header.Get("Authorization"))

			// Verify request body
			var webhookReq WebhookRequest
			if err := json.NewDecoder(req.Body).Decode(&webhookReq); !assert.NoError(t, err) {
				return tu.StringResponse(http.StatusOK, ""), nil
			}
			assert.Equal(t, "https://example.com/webhook", webhookReq.URL)
			assert.Equal(t, "Bearer", webhookReq.RequiredAuth.Type)
			assert.Equal(t, "webhook-auth-token", webhookReq.RequiredAuth.Token)
			assert.Equal(t, "Authorization", webhookReq.RequiredAuth.Header)

			// Write mock response
			return tu.JSONResponse(t, http.StatusOK, expectedWebhook), nil
		},
	}

	client := &Client{
		Url:        "https://headers.test",
		ApiKey:     "test-api-key",
		httpClient: mock,
	}

	ctx := context.Background()
	webhook, err := client.RegisterWebhook(ctx, "https://example.com/webhook", "webhook-auth-token")
	require.NoError(t, err)
	require.NotNil(t, webhook)
	require.Equal(t, expectedWebhook.URL, webhook.URL)
	require.Equal(t, expectedWebhook.Active, webhook.Active)
}

func TestRegisterWebhookError(t *testing.T) {
	t.Parallel()

	mock := &tu.MockHTTPClient{
		DoFunc: func(_ *http.Request) (*http.Response, error) {
			return tu.StringResponse(http.StatusBadRequest, "Invalid webhook URL"), nil
		},
	}

	client := &Client{
		Url:        "https://headers.test",
		ApiKey:     "test-api-key",
		httpClient: mock,
	}

	ctx := context.Background()
	webhook, err := client.RegisterWebhook(ctx, "invalid-url", "token")
	require.Error(t, err)
	require.Nil(t, webhook)
	require.Contains(t, err.Error(), "failed to register webhook")
}

func TestUnregisterWebhookSuccess(t *testing.T) {
	t.Parallel()

	callbackURL := "https://example.com/webhook"

	mock := &tu.MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			// Verify request method and path
			assert.Equal(t, http.MethodDelete, req.Method)
			assert.Equal(t, "/api/v1/webhook", req.URL.Path)

			// Verify query parameter
			urlParam := req.URL.Query().Get("url")
			assert.Equal(t, callbackURL, urlParam)

			// Verify Authorization header
			assert.Equal(t, "Bearer test-api-key", req.Header.Get("Authorization"))

			// Write success response
			return tu.StringResponse(http.StatusOK, ""), nil
		},
	}

	client := &Client{
		Url:        "https://headers.test",
		ApiKey:     "test-api-key",
		httpClient: mock,
	}

	ctx := context.Background()
	err := client.UnregisterWebhook(ctx, callbackURL)
	require.NoError(t, err)
}

func TestUnregisterWebhookError(t *testing.T) {
	t.Parallel()

	mock := &tu.MockHTTPClient{
		DoFunc: func(_ *http.Request) (*http.Response, error) {
			return tu.StringResponse(http.StatusNotFound, "Webhook not found"), nil
		},
	}

	client := &Client{
		Url:        "https://headers.test",
		ApiKey:     "test-api-key",
		httpClient: mock,
	}

	ctx := context.Background()
	err := client.UnregisterWebhook(ctx, "https://example.com/webhook")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to unregister webhook")
}

func TestGetWebhookSuccess(t *testing.T) {
	t.Parallel()

	expectedWebhook := Webhook{
		URL:               "https://example.com/webhook",
		CreatedAt:         "2025-09-19T22:27:00Z",
		LastEmitStatus:    "success",
		LastEmitTimestamp: "2025-09-19T23:00:00Z",
		ErrorsCount:       0,
		Active:            true,
	}

	mock := &tu.MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			// Verify request method and path
			assert.Equal(t, http.MethodGet, req.Method)
			assert.Equal(t, "/api/v1/webhook", req.URL.Path)

			// Verify query parameter
			urlParam := req.URL.Query().Get("url")
			assert.Equal(t, expectedWebhook.URL, urlParam)

			// Verify Authorization header
			assert.Equal(t, "Bearer test-api-key", req.Header.Get("Authorization"))

			// Write mock response
			return tu.JSONResponse(t, http.StatusOK, expectedWebhook), nil
		},
	}

	client := &Client{
		Url:        "https://headers.test",
		ApiKey:     "test-api-key",
		httpClient: mock,
	}

	ctx := context.Background()
	webhook, err := client.GetWebhook(ctx, expectedWebhook.URL)
	require.NoError(t, err)
	require.NotNil(t, webhook)
	require.Equal(t, expectedWebhook.URL, webhook.URL)
	require.Equal(t, expectedWebhook.Active, webhook.Active)
	require.Equal(t, expectedWebhook.ErrorsCount, webhook.ErrorsCount)
}

func TestGetWebhookNotFound(t *testing.T) {
	t.Parallel()

	mock := &tu.MockHTTPClient{
		DoFunc: func(_ *http.Request) (*http.Response, error) {
			return tu.StringResponse(http.StatusNotFound, "Webhook not found"), nil
		},
	}

	client := &Client{
		Url:        "https://headers.test",
		ApiKey:     "test-api-key",
		httpClient: mock,
	}

	ctx := context.Background()
	webhook, err := client.GetWebhook(ctx, "https://example.com/webhook")
	require.Error(t, err)
	require.Nil(t, webhook)
	require.Contains(t, err.Error(), "failed to get webhook")
}

func TestGetWebhookInvalidJSON(t *testing.T) {
	t.Parallel()

	mock := &tu.MockHTTPClient{
		DoFunc: func(_ *http.Request) (*http.Response, error) {
			return tu.StringResponse(http.StatusOK, "invalid json"), nil
		},
	}

	client := &Client{
		Url:        "https://headers.test",
		ApiKey:     "test-api-key",
		httpClient: mock,
	}

	ctx := context.Background()
	webhook, err := client.GetWebhook(ctx, "https://example.com/webhook")
	require.Error(t, err)
	require.Nil(t, webhook)
	require.Contains(t, err.Error(), "error decoding response")
}

func TestRegisterWebhookInvalidJSON(t *testing.T) {
	t.Parallel()

	mock := &tu.MockHTTPClient{
		DoFunc: func(_ *http.Request) (*http.Response, error) {
			return tu.StringResponse(http.StatusOK, "invalid json"), nil
		},
	}

	client := &Client{
		Url:        "https://headers.test",
		ApiKey:     "test-api-key",
		httpClient: mock,
	}

	ctx := context.Background()
	webhook, err := client.RegisterWebhook(ctx, "https://example.com/webhook", "token")
	require.Error(t, err)
	require.Nil(t, webhook)
	require.Contains(t, err.Error(), "error decoding response")
}

func TestGetMerkleRootsInvalidJSON(t *testing.T) {
	t.Parallel()

	mock := &tu.MockHTTPClient{
		DoFunc: func(_ *http.Request) (*http.Response, error) {
			return tu.StringResponse(http.StatusOK, "invalid json"), nil
		},
	}

	client := &Client{
		Url:        "https://headers.test",
		ApiKey:     "test-api-key",
		httpClient: mock,
	}

	ctx := context.Background()
	roots, err := client.GetMerkleRoots(ctx, 10, nil)
	require.Error(t, err)
	require.Nil(t, roots)
}

func TestGetMerkleRootsEmptyResponse(t *testing.T) {
	t.Parallel()

	mock := &tu.MockHTTPClient{
		DoFunc: func(_ *http.Request) (*http.Response, error) {
			response := struct {
				Content []MerkleRootInfo `json:"content"`
				Page    struct {
					LastEvaluatedKey string `json:"lastEvaluatedKey"`
				} `json:"page"`
			}{
				Content: []MerkleRootInfo{},
			}
			return tu.JSONResponse(t, http.StatusOK, response), nil
		},
	}

	client := &Client{
		Url:        "https://headers.test",
		ApiKey:     "test-api-key",
		httpClient: mock,
	}

	ctx := context.Background()
	roots, err := client.GetMerkleRoots(ctx, 10, nil)
	require.NoError(t, err)
	require.Empty(t, roots)
}

func TestWebhookWithMultipleErrorCounts(t *testing.T) {
	t.Parallel()

	// Test webhook with various error counts
	testCases := []struct {
		name        string
		errorsCount int
		lastStatus  string
		active      bool
	}{
		{"NoErrors", 0, "success", true},
		{"FewErrors", 3, "failed", true},
		{"ManyErrors", 10, "failed", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			expectedWebhook := Webhook{
				URL:            "https://example.com/webhook",
				ErrorsCount:    tc.errorsCount,
				LastEmitStatus: tc.lastStatus,
				Active:         tc.active,
			}

			mock := &tu.MockHTTPClient{
				DoFunc: func(_ *http.Request) (*http.Response, error) {
					return tu.JSONResponse(t, http.StatusOK, expectedWebhook), nil
				},
			}

			client := &Client{
				Url:        "https://headers.test",
				ApiKey:     "test-api-key",
				httpClient: mock,
			}

			ctx := context.Background()
			webhook, err := client.GetWebhook(ctx, expectedWebhook.URL)
			require.NoError(t, err)
			require.Equal(t, tc.errorsCount, webhook.ErrorsCount)
			require.Equal(t, tc.lastStatus, webhook.LastEmitStatus)
			require.Equal(t, tc.active, webhook.Active)
		})
	}
}
