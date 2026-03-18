package transports

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/brc104"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetRegisteredOnData covers GetRegisteredOnData
func TestGetRegisteredOnData(t *testing.T) {
	t.Run("returns error when no handlers are registered", func(t *testing.T) {
		transport, err := NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{
			BaseURL: "http://example.com",
		})
		require.NoError(t, err)

		handler, err := transport.GetRegisteredOnData()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no handlers registered")
		assert.Nil(t, handler)
	})

	t.Run("returns first registered handler", func(t *testing.T) {
		transport, err := NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{
			BaseURL: "http://example.com",
		})
		require.NoError(t, err)

		called := false
		handlerFn := func(ctx context.Context, msg *auth.AuthMessage) error {
			called = true
			return nil
		}

		err = transport.OnData(handlerFn)
		require.NoError(t, err)

		handler, err := transport.GetRegisteredOnData()
		require.NoError(t, err)
		require.NotNil(t, handler)

		// Invoke the returned handler and verify it is the one we registered
		err = handler(context.Background(), &auth.AuthMessage{})
		require.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("returns first handler even when multiple are registered", func(t *testing.T) {
		transport, err := NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{
			BaseURL: "http://example.com",
		})
		require.NoError(t, err)

		firstCalled := false
		secondCalled := false

		err = transport.OnData(func(ctx context.Context, msg *auth.AuthMessage) error {
			firstCalled = true
			return nil
		})
		require.NoError(t, err)

		err = transport.OnData(func(ctx context.Context, msg *auth.AuthMessage) error {
			secondCalled = true
			return nil
		})
		require.NoError(t, err)

		handler, err := transport.GetRegisteredOnData()
		require.NoError(t, err)

		err = handler(context.Background(), &auth.AuthMessage{})
		require.NoError(t, err)

		assert.True(t, firstCalled, "first handler should be called")
		assert.False(t, secondCalled, "second handler should not be called via GetRegisteredOnData")
	})
}

// TestAuthMessageFromNonGeneralMessageResponse covers the private method indirectly
// by sending non-general messages through the transport.
func TestAuthMessageFromNonGeneralMessageResponse(t *testing.T) {
	pubKeyHex := "02bbc996771abe50be940a9cfd91d6f28a70d139f340bedc8cdd4f236e5e9c9889"
	pubKey, err := ec.PublicKeyFromString(pubKeyHex)
	require.NoError(t, err)

	makeTransportWithHandler := func(t *testing.T, serverURL string) *SimplifiedHTTPTransport {
		transport, err := NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{
			BaseURL: serverURL,
		})
		require.NoError(t, err)
		err = transport.OnData(func(ctx context.Context, msg *auth.AuthMessage) error {
			return nil
		})
		require.NoError(t, err)
		return transport
	}

	t.Run("non-general message fails when server returns non-2xx", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized"))
		}))
		defer server.Close()

		transport := makeTransportWithHandler(t, server.URL)
		msg := &auth.AuthMessage{
			Version:     "0.1",
			MessageType: auth.MessageTypeInitialRequest,
			IdentityKey: pubKey,
		}

		err = transport.Send(context.Background(), msg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to authenticate")
	})

	t.Run("non-general message fails when response body is empty (ContentLength=0)", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		transport := makeTransportWithHandler(t, server.URL)
		msg := &auth.AuthMessage{
			Version:     "0.1",
			MessageType: auth.MessageTypeInitialRequest,
			IdentityKey: pubKey,
		}

		err = transport.Send(context.Background(), msg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty response body")
	})

	t.Run("non-general message fails when response body is invalid JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("not valid json"))
		}))
		defer server.Close()

		transport := makeTransportWithHandler(t, server.URL)
		msg := &auth.AuthMessage{
			Version:     "0.1",
			MessageType: auth.MessageTypeInitialRequest,
			IdentityKey: pubKey,
		}

		err = transport.Send(context.Background(), msg)
		assert.Error(t, err)
	})

	t.Run("non-general message succeeds when response is valid AuthMessage JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			// Return a valid AuthMessage JSON with proper identity key
			_, _ = w.Write([]byte(`{"version":"0.1","messageType":"initialResponse","identityKey":"02bbc996771abe50be940a9cfd91d6f28a70d139f340bedc8cdd4f236e5e9c9889"}`))
		}))
		defer server.Close()

		received := false
		transport, err := NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{
			BaseURL: server.URL,
		})
		require.NoError(t, err)
		err = transport.OnData(func(ctx context.Context, msg *auth.AuthMessage) error {
			received = true
			return nil
		})
		require.NoError(t, err)

		msg := &auth.AuthMessage{
			Version:     "0.1",
			MessageType: auth.MessageTypeInitialRequest,
			IdentityKey: pubKey,
		}

		err = transport.Send(context.Background(), msg)
		assert.NoError(t, err)
		assert.True(t, received)
	})
}

// TestAuthMessageFromGeneralMessageResponse covers the private method via Send with general message type.
func TestAuthMessageFromGeneralMessageResponse(t *testing.T) {
	pubKeyHex := "02bbc996771abe50be940a9cfd91d6f28a70d139f340bedc8cdd4f236e5e9c9889"
	pubKey, err := ec.PublicKeyFromString(pubKeyHex)
	require.NoError(t, err)

	requestID := make([]byte, 32)
	copy(requestID, "test-request-id-123456789012345")
	payload := encodeGeneralPayload(requestID, "POST", "/test", "", map[string]string{"Content-Type": "application/json"}, []byte(`{}`))

	makeTransportWithServer := func(t *testing.T, server *httptest.Server) (*SimplifiedHTTPTransport, func()) {
		transport, err := NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{
			BaseURL: server.URL,
		})
		require.NoError(t, err)
		err = transport.OnData(func(ctx context.Context, msg *auth.AuthMessage) error {
			return nil
		})
		require.NoError(t, err)
		return transport, server.Close
	}

	t.Run("fails when version header is missing", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// No version header set
			w.WriteHeader(http.StatusOK)
		}))
		transport, cleanup := makeTransportWithServer(t, server)
		defer cleanup()

		msg := &auth.AuthMessage{
			Version:     "0.1",
			MessageType: auth.MessageTypeGeneral,
			IdentityKey: pubKey,
			Payload:     payload,
		}

		err = transport.Send(context.Background(), msg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing version header")
	})

	t.Run("fails when identity key header is missing", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(brc104.HeaderVersion, "0.1")
			// No identity key header
			w.WriteHeader(http.StatusOK)
		}))
		transport, cleanup := makeTransportWithServer(t, server)
		defer cleanup()

		msg := &auth.AuthMessage{
			Version:     "0.1",
			MessageType: auth.MessageTypeGeneral,
			IdentityKey: pubKey,
			Payload:     payload,
		}

		err = transport.Send(context.Background(), msg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing identity key header")
	})

	t.Run("fails when identity key header is invalid hex", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(brc104.HeaderVersion, "0.1")
			w.Header().Set(brc104.HeaderIdentityKey, "not-a-valid-pubkey")
			w.WriteHeader(http.StatusOK)
		}))
		transport, cleanup := makeTransportWithServer(t, server)
		defer cleanup()

		msg := &auth.AuthMessage{
			Version:     "0.1",
			MessageType: auth.MessageTypeGeneral,
			IdentityKey: pubKey,
			Payload:     payload,
		}

		err = transport.Send(context.Background(), msg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid identity key format")
	})

	t.Run("fails when signature header is not valid hex", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(brc104.HeaderVersion, "0.1")
			w.Header().Set(brc104.HeaderIdentityKey, pubKeyHex)
			w.Header().Set(brc104.HeaderSignature, "not-hex!!!")
			w.WriteHeader(http.StatusOK)
		}))
		transport, cleanup := makeTransportWithServer(t, server)
		defer cleanup()

		msg := &auth.AuthMessage{
			Version:     "0.1",
			MessageType: auth.MessageTypeGeneral,
			IdentityKey: pubKey,
			Payload:     payload,
		}

		err = transport.Send(context.Background(), msg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signature format")
	})

	t.Run("fails when message type in response is unexpected non-general type", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(brc104.HeaderVersion, "0.1")
			w.Header().Set(brc104.HeaderIdentityKey, pubKeyHex)
			w.Header().Set(brc104.HeaderSignature, hex.EncodeToString([]byte{}))
			w.Header().Set(brc104.HeaderMessageType, "initialRequest") // non-general type
			w.WriteHeader(http.StatusOK)
		}))
		transport, cleanup := makeTransportWithServer(t, server)
		defer cleanup()

		msg := &auth.AuthMessage{
			Version:     "0.1",
			MessageType: auth.MessageTypeGeneral,
			IdentityKey: pubKey,
			Payload:     payload,
		}

		err = transport.Send(context.Background(), msg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "non-general message type")
	})

	t.Run("succeeds with valid general message response headers", func(t *testing.T) {
		received := false
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(brc104.HeaderVersion, "0.1")
			w.Header().Set(brc104.HeaderIdentityKey, pubKeyHex)
			w.Header().Set(brc104.HeaderSignature, hex.EncodeToString([]byte{}))
			w.Header().Set(brc104.HeaderRequestID, r.Header.Get(brc104.HeaderRequestID))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		transport, err := NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{
			BaseURL: server.URL,
		})
		require.NoError(t, err)
		err = transport.OnData(func(ctx context.Context, msg *auth.AuthMessage) error {
			received = true
			return nil
		})
		require.NoError(t, err)

		msg := &auth.AuthMessage{
			Version:     "0.1",
			MessageType: auth.MessageTypeGeneral,
			IdentityKey: pubKey,
			Payload:     payload,
		}

		err = transport.Send(context.Background(), msg)
		assert.NoError(t, err)
		assert.True(t, received)
	})
}
