package substrates

import (
	"encoding/json"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHTTPWalletJSON(t *testing.T) {
	tests := []struct {
		name       string
		originator string
		baseURL    string
		client     *http.Client
		wantURL    string
	}{
		{
			name:       "default values",
			originator: TestOriginator,
			baseURL:    "",
			client:     nil,
			wantURL:    "http://localhost:3321",
		},
		{
			name:       "custom values",
			originator: "app.test",
			baseURL:    "https://wallet.example.com",
			client:     &http.Client{},
			wantURL:    "https://wallet.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewHTTPWalletJSON(tt.originator, tt.baseURL, tt.client)
			require.Equal(t, tt.wantURL, client.baseURL, "baseURL mismatch")
			require.Equal(t, tt.originator, client.originator, "originator mismatch")
			if tt.client == nil {
				require.Same(t, http.DefaultClient, client.httpClient, "expected default HTTP client")
			} else {
				require.Same(t, tt.client, client.httpClient, "expected custom HTTP client")
			}
		})
	}
}

func TestHTTPWalletJSON_API(t *testing.T) {
	// Test server that validates requests and returns mock responses
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate headers
		require.Equal(t, r.Header.Get("Accept"), "application/json")
		require.Equal(t, r.Header.Get("Content-Type"), "application/json")
		require.Equal(t, r.Header.Get("Originator"), TestOriginator)
		require.Equal(t, r.URL.Path, "/testEndpoint")

		// Validate body
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var req map[string]interface{}
		err = json.Unmarshal(body, &req)
		require.NoError(t, err)
		require.Equal(t, "testValue", req["testKey"])

		// Return test response
		resp := map[string]string{"result": "success"}
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(resp)
		require.NoError(t, err)
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON(TestOriginator, ts.URL, nil)

	// Test successful API call
	args := map[string]string{"testKey": "testValue"}
	data, err := client.api("testEndpoint", args)
	require.NoError(t, err, "api call failed")

	var result map[string]string
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)
	require.Equal(t, "success", result["result"])
}

func TestHTTPWalletJSON_API_Errors(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		response   string
		wantErr    string
	}{
		{
			name:       "HTTP error",
			statusCode: http.StatusInternalServerError,
			response:   `{"message": "server error"}`,
			wantErr:    "HTTP request failed with status 500",
		},
		{
			name:       "invalid JSON request",
			statusCode: http.StatusBadRequest,
			response:   `{"error": "invalid request"}`,
			wantErr:    "HTTP request failed with status 400",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, err := w.Write([]byte(tt.response))
				require.NoError(t, err)
			}))
			defer ts.Close()

			client := NewHTTPWalletJSON(TestOriginator, ts.URL, nil)
			_, err := client.api("testEndpoint", map[string]string{"key": "value"})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TODO: Similar test patterns would be implemented for all other wallet methods
func TestHTTPWalletJSON_CreateAction(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/createAction", r.URL.Path)

		var args wallet.CreateActionArgs
		err := json.NewDecoder(r.Body).Decode(&args)
		require.NoError(t, err)
		require.Equal(t, "test desc", args.Description)

		resp := wallet.CreateActionResult{Txid: "test-txid"}
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(resp)
		require.NoError(t, err)
	}))
	defer ts.Close()

	client := NewHTTPWalletJSON("", ts.URL, nil)
	result, err := client.CreateAction(wallet.CreateActionArgs{
		Description: "test desc",
	}, "")
	require.NoError(t, err)
	require.Equal(t, "test-txid", result.Txid)
}

func TestHTTPWalletJSON_ErrorCases(t *testing.T) {
	// Test JSON marshaling error
	t.Run("marshal error", func(t *testing.T) {
		client := NewHTTPWalletJSON("", "", nil)
		// Pass a channel which can't be marshaled to JSON
		_, err := client.api("test", make(chan int))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to marshal request")
	})

	// Test HTTP request error
	t.Run("HTTP error", func(t *testing.T) {
		client := NewHTTPWalletJSON("", "http://invalid-url", nil)
		_, err := client.api("test", map[string]string{"key": "value"})
		require.Error(t, err)
	})

	// Test invalid JSON response
	t.Run("invalid JSON response", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("invalid json"))
		}))
		defer ts.Close()

		client := NewHTTPWalletJSON("", ts.URL, nil)
		_, err := client.CreateAction(wallet.CreateActionArgs{}, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
	})
}

