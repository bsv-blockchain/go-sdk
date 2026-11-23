package transports

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/brc104"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

const testHTTPExampleURL = "http://example.com"

// TestGetRegisteredOnData covers GetRegisteredOnData
func TestGetRegisteredOnData(t *testing.T) {
	t.Run("returns error when no handlers are registered", func(t *testing.T) {
		transport, err := NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{
			BaseURL: testHTTPExampleURL,
		})
		require.NoError(t, err)

		handler, err := transport.GetRegisteredOnData()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no handlers registered")
		assert.Nil(t, handler)
	})

	t.Run("returns first registered handler", func(t *testing.T) {
		transport, err := NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{
			BaseURL: testHTTPExampleURL,
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
			BaseURL: testHTTPExampleURL,
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
		transport, transportErr := NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{
			BaseURL: serverURL,
		})
		require.NoError(t, transportErr)
		transportErr = transport.OnData(func(ctx context.Context, msg *auth.AuthMessage) error {
			return nil
		})
		require.NoError(t, transportErr)
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
		require.Error(t, err)
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
		require.Error(t, err)
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
		require.Error(t, err)
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
		require.NoError(t, err)
		assert.True(t, received)
	})
}

// TestSimplifiedHTTPTransportSendEmptyNonInitialReply covers a server that
// answers a non-initialRequest message with 2xx and no AuthMessage. BRC-104
// allows that, and it is how a handshake finishes after certificateResponse.
func TestSimplifiedHTTPTransportSendEmptyNonInitialReply(t *testing.T) {
	pubKeyHex := "02bbc996771abe50be940a9cfd91d6f28a70d139f340bedc8cdd4f236e5e9c9889"
	pubKey, err := ec.PublicKeyFromString(pubKeyHex)
	require.NoError(t, err)

	const replyBody = `{"version":"0.1","messageType":"initialResponse","identityKey":"02bbc996771abe50be940a9cfd91d6f28a70d139f340bedc8cdd4f236e5e9c9889"}`

	tests := []struct {
		name            string
		messageType     auth.MessageType
		status          int
		body            string
		wantErrContains string
		wantAuthErr     bool
		wantHandler     bool
	}{
		{
			name:        "certificateResponse with empty 200 succeeds and does not dispatch",
			messageType: auth.MessageTypeCertificateResponse,
			status:      http.StatusOK,
		},
		{
			name:        "certificateRequest with empty 200 succeeds and does not dispatch",
			messageType: auth.MessageTypeCertificateRequest,
			status:      http.StatusOK,
		},
		{
			name:        "initialResponse with empty 204 succeeds and does not dispatch",
			messageType: auth.MessageTypeInitialResponse,
			status:      http.StatusNoContent,
		},
		{
			name:            "initialRequest with empty 200 still fails",
			messageType:     auth.MessageTypeInitialRequest,
			status:          http.StatusOK,
			wantErrContains: "empty response body",
		},
		{
			name:        "certificateResponse with non-2xx still fails",
			messageType: auth.MessageTypeCertificateResponse,
			status:      http.StatusUnauthorized,
			body:        "unauthorized",
			wantAuthErr: true,
		},
		{
			name:        "certificateResponse with a JSON body is still dispatched",
			messageType: auth.MessageTypeCertificateResponse,
			status:      http.StatusOK,
			body:        replyBody,
			wantHandler: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverHit := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				serverHit = true
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "/.well-known/auth", r.URL.Path)
				w.WriteHeader(tt.status)
				if tt.body != "" {
					_, writeErr := w.Write([]byte(tt.body))
					assert.NoError(t, writeErr)
				}
			}))
			defer server.Close()

			handlerCalled := false
			var gotType auth.MessageType
			transport, transportErr := NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{
				BaseURL: server.URL,
			})
			require.NoError(t, transportErr)
			require.NoError(t, transport.OnData(func(_ context.Context, msg *auth.AuthMessage) error {
				handlerCalled = true
				gotType = msg.MessageType
				return nil
			}))

			sendErr := transport.Send(t.Context(), &auth.AuthMessage{
				Version:     "0.1",
				MessageType: tt.messageType,
				IdentityKey: pubKey,
			})

			assert.True(t, serverHit, "the message must be posted before the result is decided")
			if tt.wantAuthErr {
				require.ErrorIs(t, sendErr, ErrHTTPServerFailedToAuthenticate)
				assert.False(t, handlerCalled)
				return
			}
			if tt.wantErrContains != "" {
				require.ErrorContains(t, sendErr, tt.wantErrContains)
				assert.False(t, handlerCalled)
				return
			}
			require.NoError(t, sendErr)
			assert.Equal(t, tt.wantHandler, handlerCalled)
			if tt.wantHandler {
				assert.Equal(t, auth.MessageTypeInitialResponse, gotType)
			}
		})
	}
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
		transport, transportErr := NewSimplifiedHTTPTransport(&SimplifiedHTTPTransportOptions{
			BaseURL: server.URL,
		})
		require.NoError(t, transportErr)
		transportErr = transport.OnData(func(ctx context.Context, msg *auth.AuthMessage) error {
			return nil
		})
		require.NoError(t, transportErr)
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
		require.Error(t, err)
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
		require.Error(t, err)
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
		require.Error(t, err)
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
		require.Error(t, err)
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
		require.Error(t, err)
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
		require.NoError(t, err)
		assert.True(t, received)
	})
}
