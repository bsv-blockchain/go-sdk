package authhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// MockPeer implements the PeerInterface for testing
type MockPeer struct {
	toPeerCalled      bool
	lastMessage       []byte
	lastIdentityKey   string
	lastMaxWaitTimeMs int
}

func (m *MockPeer) ToPeer(message []byte, identityKey string, maxWaitTimeMs int) error {
	m.toPeerCalled = true
	m.lastMessage = message
	m.lastIdentityKey = identityKey
	m.lastMaxWaitTimeMs = maxWaitTimeMs
	return nil
}

func TestNew(t *testing.T) {
	mockPeer := &MockPeer{}

	// Test with valid options
	client, err := New(Options{
		BaseURL: "http://example.com",
		Peer:    mockPeer,
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if client == nil {
		t.Error("Expected client to be created")
	}

	// Test with missing BaseURL
	_, err = New(Options{
		Peer: mockPeer,
	})

	if err == nil {
		t.Error("Expected error for missing BaseURL")
	}

	// Test with missing Peer
	_, err = New(Options{
		BaseURL: "http://example.com",
	})

	if err == nil {
		t.Error("Expected error for missing Peer")
	}
}

func TestRequest(t *testing.T) {
	mockPeer := &MockPeer{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success": true}`))
	}))
	defer server.Close()

	client, err := New(Options{
		BaseURL: server.URL,
		Peer:    mockPeer,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test GET request
	resp, err := client.Get("/test", "test-identity-key", nil)
	if err != nil {
		t.Errorf("Expected no error for GET, got %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
	if !mockPeer.toPeerCalled {
		t.Error("Expected ToPeer to be called")
	}
	if mockPeer.lastIdentityKey != "test-identity-key" {
		t.Errorf("Expected identity key 'test-identity-key', got '%s'", mockPeer.lastIdentityKey)
	}

	// Reset mock
	mockPeer.toPeerCalled = false

	// Test POST request with body
	type TestBody struct {
		Name string `json:"name"`
	}
	body := TestBody{Name: "Test Name"}

	resp, err = client.Post("/test", body, "test-identity-key", nil)
	if err != nil {
		t.Errorf("Expected no error for POST, got %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
	if !mockPeer.toPeerCalled {
		t.Error("Expected ToPeer to be called")
	}

	// Test with query parameters
	mockPeer.toPeerCalled = false
	_, err = client.Get("/test", "test-identity-key", &RequestOptions{
		QueryParams: map[string]string{
			"param1": "value1",
			"param2": "value2",
		},
	})
	if err != nil {
		t.Errorf("Expected no error for GET with query params, got %v", err)
	}
	if !mockPeer.toPeerCalled {
		t.Error("Expected ToPeer to be called")
	}

	// Test with custom headers
	mockPeer.toPeerCalled = false
	_, err = client.Get("/test", "test-identity-key", &RequestOptions{
		Headers: map[string]string{
			"X-Custom-Header": "CustomValue",
		},
	})
	if err != nil {
		t.Errorf("Expected no error for GET with custom headers, got %v", err)
	}
	if !mockPeer.toPeerCalled {
		t.Error("Expected ToPeer to be called")
	}
}
