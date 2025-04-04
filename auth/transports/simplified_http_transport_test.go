package transports

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bsv-blockchain/go-sdk/auth"
)

func TestNewSimplifiedHTTPTransport(t *testing.T) {
	// Test with valid options
	transport, err := NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{
		URL: "http://example.com",
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if transport == nil {
		t.Fatal("Expected transport to be created")
	}

	if transport.url != "http://example.com" {
		t.Errorf("Expected URL to be 'http://example.com', got '%s'", transport.url)
	}

	// Test with missing URL
	_, err = NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{})
	if err == nil {
		t.Error("Expected error for missing URL")
	}
}

func TestSimplifiedHTTPTransportSend(t *testing.T) {
	// Create a test server
	var receivedMessage *auth.AuthMessage

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the request
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		// Decode the message
		var msg auth.AuthMessage
		err := json.NewDecoder(r.Body).Decode(&msg)
		if err != nil {
			t.Errorf("Failed to decode message: %v", err)
		}

		receivedMessage = &msg

		// Send a response
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create the transport
	transport, err := NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{
		URL: server.URL,
	})
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}

	// Create a test message
	testMessage := &auth.AuthMessage{
		Version:     "0.1",
		MessageType: auth.MessageTypeGeneral,
		Payload:     []byte("test payload"),
	}

	// Send the message
	err = transport.Send(testMessage)
	if err != nil {
		t.Errorf("Failed to send message: %v", err)
	}

	// Verify the message was received
	if receivedMessage == nil {
		t.Fatal("Expected message to be received by the server")
	}

	if receivedMessage.Version != "0.1" {
		t.Errorf("Expected version '0.1', got '%s'", receivedMessage.Version)
	}

	if receivedMessage.MessageType != auth.MessageTypeGeneral {
		t.Errorf("Expected message type 'general', got '%s'", receivedMessage.MessageType)
	}
}

func TestSimplifiedHTTPTransportOnData(t *testing.T) {
	transport, err := NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{
		URL: "http://example.com",
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
