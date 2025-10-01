// Package transports provides implementations of the auth.Transport interface
package transports

import (
	"errors"
)

// Common errors for all transports
var (
	// ErrNoHandlerRegistered is returned when trying to send a message without registering an OnData handler
	ErrNoHandlerRegistered            = errors.New("no OnData handler registered")
	ErrHTTPServerFailedToAuthenticate = errors.New("HTTP server failed to authenticate")
)
