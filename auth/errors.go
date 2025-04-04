package auth

import (
	"errors"
	"fmt"
)

// Common error types for the auth package
var (
	// ErrSessionNotFound is returned when a session is not found
	ErrSessionNotFound = errors.New("session-not-found")

	// ErrNotAuthenticated is returned when a peer is not authenticated
	ErrNotAuthenticated = errors.New("not-authenticated")

	// ErrAuthFailed is returned when authentication fails
	ErrAuthFailed = errors.New("authentication-failed")

	// ErrInvalidMessage is returned when a message is invalid
	ErrInvalidMessage = errors.New("invalid-message")

	// ErrInvalidSignature is returned when a signature is invalid
	ErrInvalidSignature = errors.New("invalid-signature")

	// ErrTimeout is returned when an operation times out
	ErrTimeout = errors.New("timeout")

	// ErrTransportNotConnected is returned when the transport is not connected
	ErrTransportNotConnected = errors.New("transport-not-connected")

	// ErrInvalidNonce is returned when a nonce is invalid
	ErrInvalidNonce = errors.New("invalid-nonce")

	// ErrCertificateValidation is returned when certificate validation fails
	ErrCertificateValidation = errors.New("certificate-validation-failed")
)

// NewAuthError creates a new authentication error with a message
func NewAuthError(msg string, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", msg, err)
	}
	return errors.New(msg)
}

// IsAuthError checks if an error is an authentication error
func IsAuthError(err error) bool {
	if err == nil {
		return false
	}

	// Check if err is one of our defined errors or wraps one of them
	authErrors := []error{
		ErrSessionNotFound,
		ErrNotAuthenticated,
		ErrAuthFailed,
		ErrInvalidMessage,
		ErrInvalidSignature,
		ErrTimeout,
		ErrTransportNotConnected,
		ErrInvalidNonce,
		ErrCertificateValidation,
	}

	for _, authErr := range authErrors {
		if errors.Is(err, authErr) {
			return true
		}
	}

	return false
}
