// Package transports provides implementations of the auth.Transport interface
package transports

import "errors"

// Common errors for all transports
var (
	// ErrNoHandlerRegistered is returned when trying to send a message without registering an OnData handler
	ErrNoHandlerRegistered = errors.New("no OnData handler registered")
)

// WebSocket transport specific errors
var (
	// ErrNotConnected is returned when trying to send a message without an active connection
	ErrNotConnected = errors.New("websocket transport not connected")

	// ErrAlreadyConnected is returned when trying to connect while already connected
	ErrAlreadyConnected = errors.New("websocket transport already connected")
)
