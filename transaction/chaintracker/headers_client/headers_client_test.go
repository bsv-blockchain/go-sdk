package headers_client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/stretchr/testify/require"
)

func TestGetMerkleRootsSuccess(t *testing.T) {
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

	// Create a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and path
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/api/v1/chain/merkleroot", r.URL.Path)

		// Verify query parameters
		batchSize := r.URL.Query().Get("batchSize")
		require.Equal(t, "10", batchSize)

		// Verify Authorization header
		auth := r.Header.Get("Authorization")
		require.Equal(t, "Bearer test-api-key", auth)

		// Write mock response
		w.WriteHeader(http.StatusOK)
		response := struct {
			Content []MerkleRootInfo `json:"content"`
			Page    struct {
				LastEvaluatedKey string `json:"lastEvaluatedKey"`
			} `json:"page"`
		}{
			Content: expectedRoots,
		}
		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	}))
	defer ts.Close()

	// Initialize Client with test server
	client := &Client{
		Url:        ts.URL,
		ApiKey:     "test-api-key",
		httpClient: ts.Client(),
	}

	ctx := context.Background()
	roots, err := client.GetMerkleRoots(ctx, 10, nil)
	require.NoError(t, err)
	require.Len(t, roots, 2)
	require.Equal(t, expectedRoots[0].MerkleRoot, roots[0].MerkleRoot)
	require.Equal(t, expectedRoots[0].BlockHeight, roots[0].BlockHeight)
}

func TestGetMerkleRootsWithLastEvaluatedKey(t *testing.T) {
	lastKey, _ := chainhash.NewHashFromHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")

	// Create a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify lastEvaluatedKey is included
		lastEvalKey := r.URL.Query().Get("lastEvaluatedKey")
		require.Equal(t, lastKey.String(), lastEvalKey)

		w.WriteHeader(http.StatusOK)
		response := struct {
			Content []MerkleRootInfo `json:"content"`
			Page    struct {
				LastEvaluatedKey string `json:"lastEvaluatedKey"`
			} `json:"page"`
		}{
			Content: []MerkleRootInfo{},
		}
		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	}))
	defer ts.Close()

	client := &Client{
		Url:        ts.URL,
		ApiKey:     "test-api-key",
		httpClient: ts.Client(),
	}

	ctx := context.Background()
	_, err := client.GetMerkleRoots(ctx, 10, lastKey)
	require.NoError(t, err)
}

func TestGetMerkleRootsError(t *testing.T) {
	// Create a test server that returns error
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal Server Error"))
	}))
	defer ts.Close()

	client := &Client{
		Url:        ts.URL,
		ApiKey:     "test-api-key",
		httpClient: ts.Client(),
	}

	ctx := context.Background()
	_, err := client.GetMerkleRoots(ctx, 10, nil)
	require.Error(t, err)
}

func TestRegisterWebhookSuccess(t *testing.T) {
	expectedWebhook := Webhook{
		URL:               "https://example.com/webhook",
		CreatedAt:         "2025-09-19T22:27:00Z",
		LastEmitStatus:    "success",
		LastEmitTimestamp: "2025-09-19T23:00:00Z",
		ErrorsCount:       0,
		Active:            true,
	}

	// Create a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and path
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/webhook", r.URL.Path)

		// Verify headers
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))
		require.Equal(t, "Bearer test-api-key", r.Header.Get("Authorization"))

		// Verify request body
		var webhookReq WebhookRequest
		err := json.NewDecoder(r.Body).Decode(&webhookReq)
		require.NoError(t, err)
		require.Equal(t, "https://example.com/webhook", webhookReq.URL)
		require.Equal(t, "Bearer", webhookReq.RequiredAuth.Type)
		require.Equal(t, "webhook-auth-token", webhookReq.RequiredAuth.Token)
		require.Equal(t, "Authorization", webhookReq.RequiredAuth.Header)

		// Write mock response
		w.WriteHeader(http.StatusOK)
		err = json.NewEncoder(w).Encode(expectedWebhook)
		require.NoError(t, err)
	}))
	defer ts.Close()

	client := &Client{
		Url:        ts.URL,
		ApiKey:     "test-api-key",
		httpClient: ts.Client(),
	}

	ctx := context.Background()
	webhook, err := client.RegisterWebhook(ctx, "https://example.com/webhook", "webhook-auth-token")
	require.NoError(t, err)
	require.NotNil(t, webhook)
	require.Equal(t, expectedWebhook.URL, webhook.URL)
	require.Equal(t, expectedWebhook.Active, webhook.Active)
}

func TestRegisterWebhookError(t *testing.T) {
	// Create a test server that returns error
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Invalid webhook URL"))
	}))
	defer ts.Close()

	client := &Client{
		Url:        ts.URL,
		ApiKey:     "test-api-key",
		httpClient: ts.Client(),
	}

	ctx := context.Background()
	webhook, err := client.RegisterWebhook(ctx, "invalid-url", "token")
	require.Error(t, err)
	require.Nil(t, webhook)
	require.Contains(t, err.Error(), "failed to register webhook")
}

func TestUnregisterWebhookSuccess(t *testing.T) {
	callbackURL := "https://example.com/webhook"

	// Create a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and path
		require.Equal(t, http.MethodDelete, r.Method)
		require.Equal(t, "/api/v1/webhook", r.URL.Path)

		// Verify query parameter
		urlParam := r.URL.Query().Get("url")
		require.Equal(t, callbackURL, urlParam)

		// Verify Authorization header
		require.Equal(t, "Bearer test-api-key", r.Header.Get("Authorization"))

		// Write success response
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := &Client{
		Url:        ts.URL,
		ApiKey:     "test-api-key",
		httpClient: ts.Client(),
	}

	ctx := context.Background()
	err := client.UnregisterWebhook(ctx, callbackURL)
	require.NoError(t, err)
}

func TestUnregisterWebhookError(t *testing.T) {
	// Create a test server that returns error
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Webhook not found"))
	}))
	defer ts.Close()

	client := &Client{
		Url:        ts.URL,
		ApiKey:     "test-api-key",
		httpClient: ts.Client(),
	}

	ctx := context.Background()
	err := client.UnregisterWebhook(ctx, "https://example.com/webhook")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to unregister webhook")
}

func TestGetWebhookSuccess(t *testing.T) {
	expectedWebhook := Webhook{
		URL:               "https://example.com/webhook",
		CreatedAt:         "2025-09-19T22:27:00Z",
		LastEmitStatus:    "success",
		LastEmitTimestamp: "2025-09-19T23:00:00Z",
		ErrorsCount:       0,
		Active:            true,
	}

	// Create a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and path
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/api/v1/webhook", r.URL.Path)

		// Verify query parameter
		urlParam := r.URL.Query().Get("url")
		require.Equal(t, expectedWebhook.URL, urlParam)

		// Verify Authorization header
		require.Equal(t, "Bearer test-api-key", r.Header.Get("Authorization"))

		// Write mock response
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(expectedWebhook)
		require.NoError(t, err)
	}))
	defer ts.Close()

	client := &Client{
		Url:        ts.URL,
		ApiKey:     "test-api-key",
		httpClient: ts.Client(),
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
	// Create a test server that returns 404
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Webhook not found"))
	}))
	defer ts.Close()

	client := &Client{
		Url:        ts.URL,
		ApiKey:     "test-api-key",
		httpClient: ts.Client(),
	}

	ctx := context.Background()
	webhook, err := client.GetWebhook(ctx, "https://example.com/webhook")
	require.Error(t, err)
	require.Nil(t, webhook)
	require.Contains(t, err.Error(), "failed to get webhook")
}

func TestGetWebhookInvalidJSON(t *testing.T) {
	// Create a test server that returns invalid JSON
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invalid json"))
	}))
	defer ts.Close()

	client := &Client{
		Url:        ts.URL,
		ApiKey:     "test-api-key",
		httpClient: ts.Client(),
	}

	ctx := context.Background()
	webhook, err := client.GetWebhook(ctx, "https://example.com/webhook")
	require.Error(t, err)
	require.Nil(t, webhook)
	require.Contains(t, err.Error(), "error decoding response")
}

func TestRegisterWebhookInvalidJSON(t *testing.T) {
	// Create a test server that returns invalid JSON
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invalid json"))
	}))
	defer ts.Close()

	client := &Client{
		Url:        ts.URL,
		ApiKey:     "test-api-key",
		httpClient: ts.Client(),
	}

	ctx := context.Background()
	webhook, err := client.RegisterWebhook(ctx, "https://example.com/webhook", "token")
	require.Error(t, err)
	require.Nil(t, webhook)
	require.Contains(t, err.Error(), "error decoding response")
}

func TestGetMerkleRootsInvalidJSON(t *testing.T) {
	// Create a test server that returns invalid JSON
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invalid json"))
	}))
	defer ts.Close()

	client := &Client{
		Url:        ts.URL,
		ApiKey:     "test-api-key",
		httpClient: ts.Client(),
	}

	ctx := context.Background()
	roots, err := client.GetMerkleRoots(ctx, 10, nil)
	require.Error(t, err)
	require.Nil(t, roots)
}

func TestGetMerkleRootsEmptyResponse(t *testing.T) {
	// Test with empty content array
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		response := struct {
			Content []MerkleRootInfo `json:"content"`
			Page    struct {
				LastEvaluatedKey string `json:"lastEvaluatedKey"`
			} `json:"page"`
		}{
			Content: []MerkleRootInfo{},
		}
		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	}))
	defer ts.Close()

	client := &Client{
		Url:        ts.URL,
		ApiKey:     "test-api-key",
		httpClient: ts.Client(),
	}

	ctx := context.Background()
	roots, err := client.GetMerkleRoots(ctx, 10, nil)
	require.NoError(t, err)
	require.Empty(t, roots)
}

func TestWebhookWithMultipleErrorCounts(t *testing.T) {
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
			expectedWebhook := Webhook{
				URL:            "https://example.com/webhook",
				ErrorsCount:    tc.errorsCount,
				LastEmitStatus: tc.lastStatus,
				Active:         tc.active,
			}

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				err := json.NewEncoder(w).Encode(expectedWebhook)
				require.NoError(t, err)
			}))
			defer ts.Close()

			client := &Client{
				Url:        ts.URL,
				ApiKey:     "test-api-key",
				httpClient: ts.Client(),
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
