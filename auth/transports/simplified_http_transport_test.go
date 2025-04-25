package transports

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSimplifiedHTTPTransport(t *testing.T) {
	// Test with valid options
	transport, err := NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{
		BaseURL: "http://example.com",
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if transport == nil {
		t.Fatal("Expected transport to be created")
		return
	}

	if transport.baseUrl != "http://example.com" {
		t.Errorf("Expected URL to be 'http://example.com', got '%s'", transport.baseUrl)
	}

	// Test with missing URL
	_, err = NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{})
	if err == nil {
		t.Error("Expected error for missing URL")
	}
}

// Helper to encode a valid general payload for the test
func encodeGeneralPayload(requestId []byte, method, path, search string, headers map[string]string, body []byte) []byte {
	w := util.NewWriter()
	w.WriteBytes(requestId)
	w.WriteString(method)
	w.WriteString(path)
	w.WriteString(search)
	w.WriteVarInt(uint64(len(headers)))
	for k, v := range headers {
		w.WriteString(k)
		w.WriteString(v)
	}
	w.WriteVarInt(uint64(len(body)))
	w.WriteBytes(body)
	return w.Buf
}

func TestSimplifiedHTTPTransportSend(t *testing.T) {
	// Create a test server
	var receivedRequest *http.Request

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// For 'general' messageType, expect a proxied HTTP request
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if r.URL.Path != "/test" {
			t.Errorf("Expected path '/test', got '%s'", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Expected Content-Type 'application/json', got '%s'", ct)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed to read request body: %v", err)
		}
		if string(body) != `{"foo":"bar"}` {
			t.Errorf("Expected body '{\"foo\":\"bar\"}', got '%s'", string(body))
		}
		receivedRequest = r
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create the transport
	transport, err := NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{
		BaseURL: server.URL,
	})
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}

	// Create a test message
	pubKeyHex := "02bbc996771abe50be940a9cfd91d6f28a70d139f340bedc8cdd4f236e5e9c9889"
	pubKey, _ := ec.PublicKeyFromString(pubKeyHex)
	requestId := make([]byte, 32)
	copy(requestId, []byte("test-request-id-123456789012345")) // pad to 32 bytes
	payload := encodeGeneralPayload(requestId, "POST", "/test", "", map[string]string{"Content-Type": "application/json"}, []byte(`{"foo":"bar"}`))
	testMessage := &auth.AuthMessage{
		Version:     "0.1",
		MessageType: auth.MessageTypeGeneral,
		IdentityKey: pubKey,
		Payload:     payload,
	}

	// Register an OnData handler to decode and check the response payload
	responseChecked := false
	err = transport.OnData(func(msg *auth.AuthMessage) error {
		if msg.MessageType != auth.MessageTypeGeneral {
			t.Errorf("Expected response message type 'general', got '%s'", msg.MessageType)
		}
		reader := util.NewReader(msg.Payload)
		status, err := reader.ReadVarInt()
		if err != nil {
			t.Errorf("Failed to read status from response payload: %v", err)
		}
		if status != 200 {
			t.Errorf("Expected status 200, got %d", status)
		}
		nHeaders, err := reader.ReadVarInt()
		if err != nil {
			t.Errorf("Failed to read nHeaders: %v", err)
		}
		headers := map[string]string{}
		for i := uint64(0); i < nHeaders; i++ {
			key, err := reader.ReadString()
			if err != nil {
				t.Errorf("Failed to read header key: %v", err)
			}
			val, err := reader.ReadString()
			if err != nil {
				t.Errorf("Failed to read header value: %v", err)
			}
			headers[key] = val
		}
		bodyLen, err := reader.ReadVarInt()
		if err != nil {
			t.Errorf("Failed to read bodyLen: %v", err)
		}
		body, err := reader.ReadBytes(int(bodyLen))
		if err != nil {
			t.Errorf("Failed to read response body: %v", err)
		}
		if string(body) != "" { // The test server sends an empty body
			t.Errorf("Expected empty response body, got '%s'", string(body))
		}
		responseChecked = true
		return nil
	})
	if err != nil {
		t.Errorf("Failed to register OnData handler: %v", err)
	}

	// Send the message
	err = transport.Send(testMessage)
	if err != nil {
		t.Errorf("Failed to send message: %v", err)
	}

	// Verify the proxied HTTP request was received
	if receivedRequest == nil {
		t.Fatal("Expected proxied HTTP request to be received by the server")
	}

	if !responseChecked {
		t.Error("OnData handler did not run or response was not checked")
	}
}

func TestSimplifiedHTTPTransportOnData(t *testing.T) {
	transport, err := NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{
		BaseURL: "http://example.com",
	})
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}

	// Test registering callbacks
	callbackCalled := false
	err = transport.OnData(func(msg *auth.AuthMessage) error {
		callbackCalled = true
		return nil
	})

	if err != nil {
		t.Errorf("Failed to register callback: %v", err)
	}

	// Test notifying handlers
	testMessage := &auth.AuthMessage{
		Version:     "0.1",
		MessageType: auth.MessageTypeGeneral,
		Payload:     []byte("test payload"),
	}

	transport.notifyHandlers(testMessage)

	if !callbackCalled {
		t.Error("Expected callback to be called")
	}
}

// TestSimplifiedHTTPTransportSendWithNoHandler tests that Send returns ErrNoHandlerRegistered when no handler is registered
func TestSimplifiedHTTPTransportSendWithNoHandler(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport, err := NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{BaseURL: server.URL})
	require.NoError(t, err)
	require.NotNil(t, transport)

	// Create a test message with a valid identity key
	pubKeyHex := "02bbc996771abe50be940a9cfd91d6f28a70d139f340bedc8cdd4f236e5e9c9889"
	pubKey, err := ec.PublicKeyFromString(pubKeyHex)
	require.NoError(t, err)

	testMessage := &auth.AuthMessage{
		Version:     "0.1-test",
		MessageType: "test-type",
		IdentityKey: pubKey,
		Payload:     []byte("hello http"),
	}

	// Send without registering a handler should fail
	err = transport.Send(testMessage)
	assert.ErrorIs(t, err, ErrNoHandlerRegistered, "Send should return ErrNoHandlerRegistered when no handler is registered")

	// Now register a handler
	err = transport.OnData(func(message *auth.AuthMessage) error {
		return nil // Do nothing in this test
	})
	require.NoError(t, err, "OnData registration should succeed")

	// Now send should not return the handler error
	// Note: It may fail for other reasons (like invalid message format), but at least not for missing handler
	err = transport.Send(testMessage)
	assert.NotErrorIs(t, err, ErrNoHandlerRegistered, "Send should not return ErrNoHandlerRegistered after a handler is registered")
}
