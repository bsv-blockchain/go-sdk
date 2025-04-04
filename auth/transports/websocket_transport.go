package transports

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/gorilla/websocket"
)

var (
	// ErrNotConnected is returned when trying to send a message without an active connection
	ErrNotConnected = errors.New("websocket transport not connected")

	// ErrAlreadyConnected is returned when trying to connect while already connected
	ErrAlreadyConnected = errors.New("websocket transport already connected")
)

// WebSocketTransport implements the Transport interface for WebSocket communication
type WebSocketTransport struct {
	url         string
	conn        *websocket.Conn
	onDataFuncs []func(*auth.AuthMessage) error
	mu          sync.Mutex
	connected   bool
	stopCh      chan struct{}
}

// WebSocketTransportOptions represents configuration options for the transport
type WebSocketTransportOptions struct {
	URL             string              // WebSocket URL (e.g. "ws://example.com/ws")
	ConnectTimeout  int                 // Connection timeout in milliseconds
	ReconnectDelay  int                 // Delay between reconnection attempts in milliseconds
	HandshakeHeader map[string][]string // Headers for the WebSocket handshake
}

// NewWebSocketTransport creates a new WebSocket transport instance
func NewWebSocketTransport(options *WebSocketTransportOptions) (*WebSocketTransport, error) {
	if options.URL == "" {
		return nil, errors.New("URL is required for WebSocket transport")
	}

	// Validate the URL
	_, err := url.Parse(options.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid WebSocket URL: %w", err)
	}

	return &WebSocketTransport{
		url:    options.URL,
		stopCh: make(chan struct{}),
	}, nil
}

// Connect establishes a WebSocket connection
func (t *WebSocketTransport) Connect() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.connected {
		return ErrAlreadyConnected
	}

	// Parse the URL
	u, err := url.Parse(t.url)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Connect to the WebSocket server
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket: %w", err)
	}

	t.conn = conn
	t.connected = true
	t.stopCh = make(chan struct{})

	// Start message receiver in a separate goroutine
	go t.receiveMessages()

	return nil
}

// Disconnect closes the WebSocket connection
func (t *WebSocketTransport) Disconnect() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.connected || t.conn == nil {
		return nil // Already disconnected
	}

	// Signal the receiver goroutine to stop
	close(t.stopCh)

	// Close the connection
	err := t.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	if err != nil {
		// Just log the error but continue with disconnect
		fmt.Printf("Error sending close message: %v\n", err)
	}

	err = t.conn.Close()
	t.conn = nil
	t.connected = false

	return err
}

// Send sends an AuthMessage via WebSocket
func (t *WebSocketTransport) Send(message *auth.AuthMessage) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.connected || t.conn == nil {
		return ErrNotConnected
	}

	// Marshal the message to JSON
	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal auth message: %w", err)
	}

	// Send the message
	err = t.conn.WriteMessage(websocket.TextMessage, jsonData)
	if err != nil {
		t.connected = false
		t.conn = nil
		return fmt.Errorf("failed to send WebSocket message: %w", err)
	}

	return nil
}

// OnData registers a callback for incoming messages
func (t *WebSocketTransport) OnData(callback func(*auth.AuthMessage) error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onDataFuncs = append(t.onDataFuncs, callback)
	return nil
}

// IsConnected returns the connection status
func (t *WebSocketTransport) IsConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected && t.conn != nil
}

// receiveMessages handles incoming WebSocket messages
func (t *WebSocketTransport) receiveMessages() {
	defer func() {
		t.mu.Lock()
		t.connected = false
		t.conn = nil
		t.mu.Unlock()
	}()

	for {
		select {
		case <-t.stopCh:
			return // Stopped by disconnect
		default:
			// Continue processing
		}

		// Set read deadline if needed
		_ = t.conn.SetReadDeadline(time.Now().Add(10 * time.Second))

		// Read message
		messageType, messageData, err := t.conn.ReadMessage()
		if err != nil {
			// Check if this is a normal closure
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return
			}

			// Handle other errors
			fmt.Printf("WebSocket read error: %v\n", err)
			return
		}

		// We only care about text messages containing JSON auth messages
		if messageType != websocket.TextMessage {
			continue
		}

		// Parse the auth message
		var authMessage auth.AuthMessage
		err = json.Unmarshal(messageData, &authMessage)
		if err != nil {
			fmt.Printf("Failed to parse auth message: %v\n", err)
			continue
		}

		// Notify handlers
		t.notifyHandlers(&authMessage)
	}
}

// notifyHandlers calls all registered callbacks with the received message
func (t *WebSocketTransport) notifyHandlers(message *auth.AuthMessage) {
	t.mu.Lock()
	handlers := make([]func(*auth.AuthMessage) error, len(t.onDataFuncs))
	copy(handlers, t.onDataFuncs)
	t.mu.Unlock()

	for _, handler := range handlers {
		err := handler(message)
		if err != nil {
			// Log the error but continue with other handlers
			fmt.Printf("Error in message handler: %v\n", err)
		}
	}
}
