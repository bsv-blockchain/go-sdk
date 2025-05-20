package substrates

import (
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const TestOriginator = "test.com"

func TestNewHTTPWalletWire(t *testing.T) {
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
			wantURL:    "http://localhost:3301",
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
			wire := NewHTTPWalletWire(tt.originator, tt.baseURL, tt.client)
			require.Equal(t, tt.wantURL, wire.baseURL, "baseURL mismatch")
			require.Equal(t, tt.originator, wire.originator, "originator mismatch")
			if tt.client == nil {
				require.Same(t, http.DefaultClient, wire.httpClient, "expected default HTTP client")
			} else {
				require.Same(t, tt.client, wire.httpClient, "expected custom HTTP client")
			}
		})
	}
}

func TestTransmitToWallet(t *testing.T) {
	// Test server that validates requests and returns mock responses
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate headers
		require.Equal(t, r.Header.Get("Content-Type"), "application/octet-stream")
		require.Equal(t, r.Header.Get("Origin"), TestOriginator)
		require.Equal(t, r.URL.Path, "/createAction")

		// Validate body
		body := make([]byte, r.ContentLength)
		_, err := r.Body.Read(body)
		if err != nil && err != io.EOF {
			require.NoError(t, err)
		}
		require.Equal(t, body, []byte("payload"))

		// Return test response
		_, err = w.Write([]byte("response"))
		require.NoError(t, err)
	}))
	defer ts.Close()

	// Create test message: [callCode][originatorLen][originator][payload]
	message := []byte{
		byte(CallCreateAction),                 // call code
		8,                                      // originator length (matches actual length)
		't', 'e', 's', 't', '.', 'c', 'o', 'm', // originator
		'p', 'a', 'y', 'l', 'o', 'a', 'd', // payload
	}

	wire := NewHTTPWalletWire(TestOriginator, ts.URL, nil)
	response, err := wire.TransmitToWallet(message)
	require.NoError(t, err, "TransmitToWallet failed")
	require.Equal(t, []byte("response"), response, "unexpected response")
}

func TestTransmitToWallet_Errors(t *testing.T) {
	tests := []struct {
		name    string
		message []byte
		wantErr string
	}{
		{
			name:    "empty message",
			message: []byte{},
			wantErr: "failed to read call code",
		},
		{
			name:    "invalid call code",
			message: []byte{0xFF},
			wantErr: "invalid call code",
		},
		{
			name:    "invalid originator length",
			message: []byte{byte(CallCreateAction), 10, 't', 'e', 's', 't'},
			wantErr: "invalid originator length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := NewHTTPWalletWire(TestOriginator, "http://localhost", &http.Client{})
			_, err := wire.TransmitToWallet(tt.message)
			require.Error(t, err, "expected error")
			require.ErrorContains(t, err, tt.wantErr, "error message mismatch")
		})
	}
}

func TestTransmitToWallet_HTTPErrors(t *testing.T) {
	// Test server that returns error status
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, err := w.Write([]byte("server error"))
		require.NoError(t, err)
	}))
	defer ts.Close()

	message := []byte{
		byte(CallCreateAction),            // call code
		0,                                 // no originator
		'p', 'a', 'y', 'l', 'o', 'a', 'd', // payload
	}

	wire := NewHTTPWalletWire("", ts.URL, nil)
	_, err := wire.TransmitToWallet(message)
	require.Error(t, err, "expected HTTP error")
	require.EqualError(t, err, "HTTP request failed with status: 500 Internal Server Error", "error message mismatch")
}
