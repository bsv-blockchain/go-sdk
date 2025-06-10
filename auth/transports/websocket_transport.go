package transports

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/bsv-blockchain/go-sdk/v2/auth"
	"golang.org/x/net/websocket"
)

// WebSocketTransport implements the Transport interface for WebSocket communication
// Parity with TypeScript: only Send and OnData methods
// Connection is managed internally and established on first Send
// No explicit Connect/Disconnect/IsConnected

type WebSocketTransport struct {
	baseUrl      string
	conn         *websocket.Conn
	onDataFuncs  []func(*auth.AuthMessage) error
	mu           sync.Mutex
	readDeadline time.Duration
}

// WebSocketTransportOptions contains configuration options for the WebSocketTransport.
type WebSocketTransportOptions struct {
	BaseURL      string
	ReadDeadline int // seconds, default 30
}

// NewWebSocketTransport creates a new WebSocket transport instance with the given options.
// The BaseURL is required and must be a valid WebSocket URL.
// If ReadDeadline is not specified or is zero, it defaults to 30 seconds.
func NewWebSocketTransport(options *WebSocketTransportOptions) (*WebSocketTransport, error) {
	if options.BaseURL == "" {
		return nil, errors.New("BaseURL is required for WebSocket transport")
	}
	_, err := url.Parse(options.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid WebSocket URL: %w", err)
	}
	readDeadline := time.Duration(options.ReadDeadline) * time.Second
	if readDeadline <= 0 {
		readDeadline = 30 * time.Second
	}
	return &WebSocketTransport{
		baseUrl:      options.BaseURL,
		readDeadline: readDeadline,
	}, nil
}

// Send sends an AuthMessage via WebSocket
func (t *WebSocketTransport) Send(message *auth.AuthMessage) error {
	t.mu.Lock()
	if len(t.onDataFuncs) == 0 {
		t.mu.Unlock()
		return errors.New("no handler registered")
	}
	conn := t.conn
	t.mu.Unlock()

	if conn == nil {
		// Establish connection on first send
		c, err := websocket.Dial(t.baseUrl, "", "http://localhost")
		if err != nil {
			return fmt.Errorf("failed to connect to WebSocket: %w", err)
		}
		t.mu.Lock()
		t.conn = c
		t.mu.Unlock()
		go t.receiveMessages()
		conn = c
	}

	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal auth message: %w", err)
	}

	_ = conn.SetDeadline(time.Now().Add(t.readDeadline))
	err = websocket.Message.Send(conn, jsonData)
	if err != nil {
		t.mu.Lock()
		t.conn = nil // Drop connection on error
		t.mu.Unlock()
		return fmt.Errorf("failed to send WebSocket message: %w", err)
	}
	return nil
}

// OnData registers a callback for incoming messages
func (t *WebSocketTransport) OnData(callback func(*auth.AuthMessage) error) error {
	if callback == nil {
		return errors.New("callback cannot be nil")
	}
	t.mu.Lock()
	t.onDataFuncs = append(t.onDataFuncs, callback)
	t.mu.Unlock()
	return nil
}

func (t *WebSocketTransport) receiveMessages() {
	t.mu.Lock()
	conn := t.conn
	handlers := make([]func(*auth.AuthMessage) error, len(t.onDataFuncs))
	copy(handlers, t.onDataFuncs)
	t.mu.Unlock()

	for {
		var messageData []byte
		err := websocket.Message.Receive(conn, &messageData)
		if err != nil {
			t.mu.Lock()
			t.conn = nil // Drop connection on error
			t.mu.Unlock()
			return
		}
		var authMessage auth.AuthMessage
		err = json.Unmarshal(messageData, &authMessage)
		if err != nil {
			continue
		}
		for _, handler := range handlers {
			_ = handler(&authMessage)
		}
	}
}
