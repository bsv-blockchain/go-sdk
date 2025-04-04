package transports

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	"github.com/bsv-blockchain/go-sdk/auth"
)

// SimplifiedHTTPTransport implements the Transport interface for HTTP communication
type SimplifiedHTTPTransport struct {
	url         string
	client      *http.Client
	onDataFuncs []func(*auth.AuthMessage) error
	mu          sync.Mutex
}

// SimplifiedHTTPTransportOptions represents configuration options for the transport
type SimplifiedHTTPTransportOptions struct {
	URL         string
	PollEnabled bool
	PollTimeout int
}

// NewSimplifiedHTTPTransport creates a new HTTP transport instance
func NewSimplifiedHTTPTransport(options *SimplifiedHTTPTransportOptions) (*SimplifiedHTTPTransport, error) {
	if options.URL == "" {
		return nil, errors.New("URL is required for HTTP transport")
	}

	return &SimplifiedHTTPTransport{
		url:    options.URL,
		client: &http.Client{},
	}, nil
}

// Send sends an AuthMessage via HTTP
func (t *SimplifiedHTTPTransport) Send(message *auth.AuthMessage) error {
	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal auth message: %w", err)
	}

	resp, err := t.client.Post(t.url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("HTTP request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// If we have a response, process it as a potential auth message
	if resp.ContentLength > 0 {
		var responseMsg auth.AuthMessage
		body, err := ioutil.ReadAll(resp.Body)
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
func (t *SimplifiedHTTPTransport) OnData(callback func(*auth.AuthMessage) error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onDataFuncs = append(t.onDataFuncs, callback)
	return nil
}

// notifyHandlers calls all registered callbacks with the received message
func (t *SimplifiedHTTPTransport) notifyHandlers(message *auth.AuthMessage) {
	t.mu.Lock()
	handlers := make([]func(*auth.AuthMessage) error, len(t.onDataFuncs))
	copy(handlers, t.onDataFuncs)
	t.mu.Unlock()

	for _, handler := range handlers {
		// Errors from handlers are not propagated to avoid breaking other handlers
		_ = handler(message)
	}
}

// StartPolling starts polling for incoming messages (stub implementation)
func (t *SimplifiedHTTPTransport) StartPolling() error {
	// This would implement long polling or periodic polling
	// Not fully implemented in this version
	return nil
}

// StopPolling stops polling for incoming messages
func (t *SimplifiedHTTPTransport) StopPolling() {
	// Stop the polling mechanism
}
