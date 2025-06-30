// whatsonchain_test.go

package chaintracker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/stretchr/testify/require"
)

func TestWhatsOnChainGetBlockHeaderSuccess(t *testing.T) {
	// Mock BlockHeader data
	expectedHeader := &BlockHeader{
		Hash:       &chainhash.Hash{},
		Height:     100,
		Version:    1,
		MerkleRoot: &chainhash.Hash{},
		Time:       1234567890,
		Nonce:      0,
		Bits:       "1d00ffff",
		PrevHash:   &chainhash.Hash{},
	}

	// Create a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check the request method and path
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET method, got %s", r.Method)
		}
		expectedPath := "/block/100/header"
		if r.URL.Path != expectedPath {
			t.Fatalf("expected path %s, got %s", expectedPath, r.URL.Path)
		}
		// Set the Authorization header if needed
		if auth := r.Header.Get("Authorization"); auth != "testapikey" {
			t.Fatalf("expected Authorization header 'testapikey', got '%s'", auth)
		}
		// Write the mock response
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(expectedHeader)
	}))
	defer ts.Close()

	// Initialize WhatsOnChain with the test server URL and client
	woc := &WhatsOnChain{
		Network: "main",
		ApiKey:  "testapikey",
		baseURL: ts.URL,
		client:  ts.Client(),
	}

	header, err := woc.GetBlockHeader(context.Background(), 100)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
		return // Add this return statement
	}
	if header == nil {
		t.Fatalf("expected header, got nil")
		return // Add this return statement
	}
	if header.Height != expectedHeader.Height {
		t.Errorf("expected height %d, got %d", expectedHeader.Height, header.Height)
	}
}

func TestWhatsOnChainGetBlockHeaderNotFound(t *testing.T) {
	// Create a test server that returns 404
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	woc := &WhatsOnChain{
		Network: "main",
		ApiKey:  "testapikey",
		baseURL: ts.URL,
		client:  ts.Client(),
	}

	header, err := woc.GetBlockHeader(context.Background(), 100)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if header != nil {
		t.Fatalf("expected nil header, got %v", header)
	}
}

func TestWhatsOnChainGetBlockHeaderErrorResponse(t *testing.T) {
	// Create a test server that returns 500 Internal Server Error
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal Server Error"))
	}))
	defer ts.Close()

	woc := &WhatsOnChain{
		Network: "main",
		ApiKey:  "testapikey",
		baseURL: ts.URL,
		client:  ts.Client(),
	}

	header, err := woc.GetBlockHeader(context.Background(), 100)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if header != nil {
		t.Fatalf("expected nil header, got %v", header)
	}
}

func TestWhatsOnChainIsValidRootForHeightSuccess(t *testing.T) {
	// Mock BlockHeader data with a known MerkleRoot
	merkleRootHash := chainhash.HashH([]byte("test merkle root"))
	expectedHeader := &BlockHeader{
		MerkleRoot: &merkleRootHash,
	}

	// Create a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(expectedHeader)
		require.NoError(t, err)
	}))
	defer ts.Close()

	woc := &WhatsOnChain{
		Network: "main",
		ApiKey:  "testapikey",
		baseURL: ts.URL,
		client:  ts.Client(),
	}

	isValid, err := woc.IsValidRootForHeight(context.Background(), &merkleRootHash, 100)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !isValid {
		t.Fatalf("expected isValid to be true, got false")
	}
}

func TestWhatsOnChainIsValidRootForHeightInvalidRoot(t *testing.T) {
	// Mock BlockHeader data with a different MerkleRoot
	merkleRootHash := chainhash.HashH([]byte("test merkle root"))
	differentMerkleRootHash := chainhash.HashH([]byte("different merkle root"))
	expectedHeader := &BlockHeader{
		MerkleRoot: &merkleRootHash,
	}

	// Create a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(expectedHeader)
		require.NoError(t, err)
	}))
	defer ts.Close()

	woc := &WhatsOnChain{
		Network: "main",
		ApiKey:  "testapikey",
		baseURL: ts.URL,
		client:  ts.Client(),
	}

	isValid, err := woc.IsValidRootForHeight(context.Background(), &differentMerkleRootHash, 100)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if isValid {
		t.Fatalf("expected isValid to be false, got true")
	}
}
