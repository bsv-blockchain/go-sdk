package transports

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/bsv-blockchain/go-sdk/auth"
)

// SimpleHTTPTransport implements the Transport interface for basic HTTP communication
type SimpleHTTPTransport struct {
	baseURL     string
	client      *http.Client
	onDataFuncs []func(*auth.AuthMessage) error
	mu          sync.Mutex
}

// SimpleHTTPTransportOptions represents configuration options for the transport
type SimpleHTTPTransportOptions struct {
	BaseURL string
	Client  *http.Client // Optional, if nil use default
}

// NewSimpleHTTPTransport creates a new HTTP transport instance
func NewSimpleHTTPTransport(options *SimpleHTTPTransportOptions) (*SimpleHTTPTransport, error) {
	if options.BaseURL == "" {
		return nil, errors.New("BaseURL is required for HTTP transport")
	}
	client := options.Client
	if client == nil {
		client = &http.Client{}
	}
	return &SimpleHTTPTransport{
		baseURL: options.BaseURL,
		client:  client,
	}, nil
}

// Send sends an AuthMessage via HTTP
func (t *SimpleHTTPTransport) Send(message *auth.AuthMessage) error {
	// Check if any handlers are registered
	t.mu.Lock()
	if len(t.onDataFuncs) == 0 {
		t.mu.Unlock()
		return ErrNoHandlerRegistered
	}
	t.mu.Unlock()

	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal auth message: %w", err)
	}

	url := t.baseURL
	if message.MessageType != "general" {
		url = t.baseURL + "/.well-known/auth"
	}

	resp, err := t.client.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// If we have a response, process it as a potential auth message
	if resp.ContentLength > 0 {
		var responseMsg auth.AuthMessage
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}

		err = json.Unmarshal(body, &responseMsg)
		if err != nil {
			// Not a valid auth message, just ignore
			return nil
		}

		// Notify handlers of the response message
		t.notifyHandlers(&responseMsg)
	}

	return nil
}

// OnData registers a callback for incoming messages
// This method will return an error only if the provided callback is nil.
// It must be called at least once before sending any messages.
func (t *SimpleHTTPTransport) OnData(callback func(*auth.AuthMessage) error) error {
	if callback == nil {
		return errors.New("callback cannot be nil")
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.onDataFuncs = append(t.onDataFuncs, callback)
	return nil
}

// notifyHandlers calls all registered callbacks with the received message
func (t *SimpleHTTPTransport) notifyHandlers(message *auth.AuthMessage) {
	t.mu.Lock()
	handlers := make([]func(*auth.AuthMessage) error, len(t.onDataFuncs))
	copy(handlers, t.onDataFuncs)
	t.mu.Unlock()

	for _, handler := range handlers {
		// Errors from handlers are not propagated to avoid breaking other handlers
		_ = handler(message)
	}
}
