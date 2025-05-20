package transports

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/websocket"
)

// testWsServer is a basic WebSocket test server
type testWsServer struct {
	server  *httptest.Server
	mu      sync.Mutex
	conns   map[*websocket.Conn]bool
	handler func(*websocket.Conn, []byte)
	t       *testing.T // Add testing.T for logging
}

// newTestWsServer creates and starts a new test WebSocket server
func newTestWsServer(t *testing.T) *testWsServer {
	s := &testWsServer{
		conns: make(map[*websocket.Conn]bool),
		t:     t, // Store testing.T
	}

	s.server = httptest.NewServer(http.HandlerFunc(s.handleWs))
	return s
}

// handleWs upgrades the connection and manages the WebSocket lifecycle
func (s *testWsServer) handleWs(w http.ResponseWriter, r *http.Request) {
	wsHandler := websocket.Handler(func(conn *websocket.Conn) {
		s.mu.Lock()
		s.conns[conn] = true
		s.mu.Unlock()

		defer func() {
			s.mu.Lock()
			delete(s.conns, conn)
			s.mu.Unlock()
			_ = conn.Close()
		}()

		for {
			var data []byte
			err := websocket.Message.Receive(conn, &data)
			if err != nil {
				// Check for expected closure types
				if strings.Contains(err.Error(), "use of closed network connection") ||
					strings.Contains(err.Error(), "EOF") {
					// Normal disconnection, no need to log
				} else {
					s.t.Logf("Test WS server read error: %v", err)
				}
				break // Exit loop on any error or closure
			}
			if s.handler != nil {
				s.handler(conn, data)
			} else {
				// Default echo handler if none provided
				if err := websocket.Message.Send(conn, data); err != nil {
					s.t.Logf("Test WS server write error: %v", err)
					break
				}
			}
		}
	})
	wsHandler.ServeHTTP(w, r)
}

// Close closes the test server and all active connections
func (s *testWsServer) Close() {
	s.server.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for conn := range s.conns {
		_ = conn.Close() // Attempt to close client connections
	}
	s.conns = make(map[*websocket.Conn]bool) // Clear map
}

// URL returns the WebSocket URL for the test server
func (s *testWsServer) URL() string {
	return "ws" + strings.TrimPrefix(s.server.URL, "http")
}

// TestNewWebSocketTransport tests the constructor
func TestNewWebSocketTransport(t *testing.T) {
	server := newTestWsServer(t) // Basic echo server
	defer server.Close()

	// Test with valid options
	options := &WebSocketTransportOptions{
		BaseURL:      server.URL(),
		ReadDeadline: 1,
	}
	transport, err := NewWebSocketTransport(options)
	require.NoError(t, err, "NewWebSocketTransport should not return error with valid options")
	require.NotNil(t, transport, "Transport should be created")

	// Test with invalid URL
	_, err = NewWebSocketTransport(&WebSocketTransportOptions{BaseURL: "::invalid"})
	require.Error(t, err, "NewWebSocketTransport should return error with invalid URL")

	// Test with missing URL
	_, err = NewWebSocketTransport(&WebSocketTransportOptions{})
	require.Error(t, err, "NewWebSocketTransport should return error with missing URL")
	require.Contains(t, err.Error(), "BaseURL is required", "Error message mismatch for missing URL")
}

func TestWebSocketTransportSendReceive(t *testing.T) {
	server := newTestWsServer(t) // Use default echo handler
	defer server.Close()

	transport, err := NewWebSocketTransport(&WebSocketTransportOptions{
		BaseURL:      server.URL(),
		ReadDeadline: 1,
	})
	require.NoError(t, err)
	require.NotNil(t, transport)

	// Register OnData handler
	receivedMsgChan := make(chan *auth.AuthMessage, 1)
	err = transport.OnData(func(message *auth.AuthMessage) error {
		select {
		case receivedMsgChan <- message:
		default:
			t.Logf("Handler channel full")
		}
		return nil
	})
	require.NoError(t, err, "OnData registration failed")

	// Test: Send with missing IdentityKey should return a clear error
	testMessageMissingKey := &auth.AuthMessage{
		Version:     "0.1-test",
		MessageType: "test-type",
		Payload:     []byte("hello websocket"),
		Nonce:       "test-nonce",
		IdentityKey: nil, // Explicitly missing
	}
	err = transport.Send(testMessageMissingKey)
	require.Error(t, err, "Send should return error if IdentityKey is missing")
	require.Contains(t, err.Error(), "IdentityKey is required", "Error message should mention IdentityKey")

	// Test: Send with valid IdentityKey should succeed
	pubKeyHex := "02bbc996771abe50be940a9cfd91d6f28a70d139f340bedc8cdd4f236e5e9c9889"
	pubKey, err := ec.PublicKeyFromString(pubKeyHex)
	require.NoError(t, err, "Failed to parse public key")
	testMessage := &auth.AuthMessage{
		Version:     "0.1-test",
		MessageType: "test-type",
		Payload:     []byte("hello websocket"),
		Nonce:       "test-nonce",
		IdentityKey: pubKey,
	}

	err = transport.Send(testMessage)
	require.NoError(t, err, "Send failed with valid IdentityKey")

	// Wait for the message to be received back by the handler (with timeout)
	select {
	case receivedMsg := <-receivedMsgChan:
		sentJSON, _ := json.Marshal(testMessage)
		receivedJSON, _ := json.Marshal(receivedMsg)
		require.JSONEq(t, string(sentJSON), string(receivedJSON), "Received message does not match sent message")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for message reception")
	}
}

func TestWebSocketTransportSendWithNoHandler(t *testing.T) {
	server := newTestWsServer(t) // Basic echo server
	defer server.Close()

	transport, err := NewWebSocketTransport(&WebSocketTransportOptions{
		BaseURL:      server.URL(),
		ReadDeadline: 1,
	})
	require.NoError(t, err)
	require.NotNil(t, transport)

	// Create a test message
	testMessage := &auth.AuthMessage{
		Version:     "0.1-test",
		MessageType: "test-type",
		Payload:     []byte("hello websocket"),
	}

	// Send without registering a handler should fail
	err = transport.Send(testMessage)
	require.Error(t, err, "Send should return error when no handler is registered")

	// Now register a handler
	err = transport.OnData(func(message *auth.AuthMessage) error {
		return nil // Do nothing in this test
	})
	require.NoError(t, err, "OnData registration should succeed")

	// Now send should not return the handler error (though it may fail for other connection-related reasons)
	// Provide a valid IdentityKey
	pubKeyHex := "02bbc996771abe50be940a9cfd91d6f28a70d139f340bedc8cdd4f236e5e9c9889"
	pubKey, err := ec.PublicKeyFromString(pubKeyHex)
	require.NoError(t, err, "Failed to parse public key")
	testMessage.IdentityKey = pubKey
	err = transport.Send(testMessage)
	require.NoError(t, err, "Send should not return error after a handler is registered")
}
