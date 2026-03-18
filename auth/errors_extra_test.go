package auth_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/stretchr/testify/require"
)

func TestIsAuthError(t *testing.T) {
	t.Run("returns false for nil error", func(t *testing.T) {
		require.False(t, auth.IsAuthError(nil))
	})

	t.Run("returns true for ErrSessionNotFound", func(t *testing.T) {
		require.True(t, auth.IsAuthError(auth.ErrSessionNotFound))
	})

	t.Run("returns true for ErrNotAuthenticated", func(t *testing.T) {
		require.True(t, auth.IsAuthError(auth.ErrNotAuthenticated))
	})

	t.Run("returns true for ErrAuthFailed", func(t *testing.T) {
		require.True(t, auth.IsAuthError(auth.ErrAuthFailed))
	})

	t.Run("returns true for ErrInvalidMessage", func(t *testing.T) {
		require.True(t, auth.IsAuthError(auth.ErrInvalidMessage))
	})

	t.Run("returns true for ErrInvalidSignature", func(t *testing.T) {
		require.True(t, auth.IsAuthError(auth.ErrInvalidSignature))
	})

	t.Run("returns true for ErrTimeout", func(t *testing.T) {
		require.True(t, auth.IsAuthError(auth.ErrTimeout))
	})

	t.Run("returns true for ErrTransportNotConnected", func(t *testing.T) {
		require.True(t, auth.IsAuthError(auth.ErrTransportNotConnected))
	})

	t.Run("returns true for ErrInvalidNonce", func(t *testing.T) {
		require.True(t, auth.IsAuthError(auth.ErrInvalidNonce))
	})

	t.Run("returns true for ErrCertificateValidation", func(t *testing.T) {
		require.True(t, auth.IsAuthError(auth.ErrCertificateValidation))
	})

	t.Run("returns true for wrapped auth error", func(t *testing.T) {
		wrapped := fmt.Errorf("outer: %w", auth.ErrAuthFailed)
		require.True(t, auth.IsAuthError(wrapped))
	})

	t.Run("returns false for non-auth error", func(t *testing.T) {
		require.False(t, auth.IsAuthError(errors.New("some random error")))
	})
}

func TestNewAuthError(t *testing.T) {
	t.Run("creates error with message only", func(t *testing.T) {
		err := auth.NewAuthError("test error", nil)
		require.Error(t, err)
		require.Equal(t, "test error", err.Error())
	})

	t.Run("creates error wrapping another error", func(t *testing.T) {
		cause := errors.New("cause")
		err := auth.NewAuthError("outer", cause)
		require.Error(t, err)
		require.Contains(t, err.Error(), "outer")
		require.Contains(t, err.Error(), "cause")
		require.ErrorIs(t, err, cause)
	})
}
