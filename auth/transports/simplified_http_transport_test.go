package transports

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/authpayload"
	"github.com/bsv-blockchain/go-sdk/auth/brc104"
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

	assert.NoError(t, err, "Expected no error")
	require.NotNil(t, transport, "Expected transport to be created")
	assert.Equal(t, "http://example.com", transport.baseUrl, "Expected URL to be 'http://example.com'")

	// Test with missing URL
	_, err = NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{})
	assert.Error(t, err, "Expected error for missing URL")
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
		assert.Equal(t, "POST", r.Method, "Expected POST request")
		assert.Equal(t, "/test", r.URL.Path, "Expected path '/test'")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"), "Expected Content-Type 'application/json'")

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err, "Failed to read request body")
		assert.Equal(t, `{"foo":"bar"}`, string(body), "Expected body '{\"foo\":\"bar\"}'")

		receivedRequest = r

		w.Header().Set(brc104.HeaderVersion, "0.1")
		w.Header().Set(brc104.HeaderIdentityKey, "02dae142239f2f2b065759cd6b3599002b5a927ba533653ccdfdafd3ae262c9410")
		w.Header().Set(brc104.HeaderRequestID, r.Header.Get(brc104.HeaderRequestID))
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
	requestID := make([]byte, 32)
	copy(requestID, "test-request-id-123456789012345") // pad to 32 bytes
	payload := encodeGeneralPayload(requestID, "POST", "/test", "", map[string]string{"Content-Type": "application/json"}, []byte(`{"foo":"bar"}`))
	testMessage := &auth.AuthMessage{
		Version:     "0.1",
		MessageType: auth.MessageTypeGeneral,
		IdentityKey: pubKey,
		Payload:     payload,
	}

	// Register an OnData handler to decode and check the response payload
	responseChecked := false
	err = transport.OnData(func(ctx context.Context, msg *auth.AuthMessage) error {
		if msg.MessageType != auth.MessageTypeGeneral {
			t.Errorf("Expected response message type 'general', got '%s'", msg.MessageType)
		}

		reqIDFromResponse, res, err := authpayload.ToSimplifiedHttpResponse(msg.Payload)
		assert.NoError(t, err, "Payload should be deserializable to response")

		assert.EqualValuesf(t, requestID, reqIDFromResponse, "Request ID from response should match this from request")

		assert.Equal(t, http.StatusOK, res.StatusCode, "Expected status code 200")

		assert.Empty(t, res.Body, "Expected empty response body")

		responseChecked = true
		return nil
	})
	if err != nil {
		t.Errorf("Failed to register OnData handler: %v", err)
	}

	// Send the message
	err = transport.Send(context.Background(), testMessage)
	assert.NoError(t, err, "Failed to send message")

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
	require.NoError(t, err, "Failed to create transport")

	// Test registering callbacks
	callbackCalled := false
	err = transport.OnData(func(ctx context.Context, msg *auth.AuthMessage) error {
		callbackCalled = true
		return nil
	})

	assert.NoError(t, err, "Failed to register callback")

	// Test notifying handlers
	testMessage := &auth.AuthMessage{
		Version:     "0.1",
		MessageType: auth.MessageTypeGeneral,
		Payload:     []byte("test payload"),
	}

	err = transport.notifyHandlers(t.Context(), testMessage)
	require.NoError(t, err, "notifyHandlers should not return error")

	assert.True(t, callbackCalled, "Expected callback to be called")
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
	err = transport.Send(t.Context(), testMessage)
	assert.ErrorIs(t, err, ErrNoHandlerRegistered, "Send should return ErrNoHandlerRegistered when no handler is registered")

	// Now register a handler
	err = transport.OnData(func(ctx context.Context, message *auth.AuthMessage) error {
		return nil // Do nothing in this test
	})
	require.NoError(t, err, "OnData registration should succeed")

	// Now send should not return the handler error
	// Note: It may fail for other reasons (like invalid message format), but at least not for missing handler
	err = transport.Send(t.Context(), testMessage)
	assert.NotErrorIs(t, err, ErrNoHandlerRegistered, "Send should not return ErrNoHandlerRegistered after a handler is registered")
}
