package transports

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/authpayload"
	"github.com/bsv-blockchain/go-sdk/auth/brc104"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	primitives "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// SimplifiedHTTPTransport implements the Transport interface for HTTP communication
type SimplifiedHTTPTransport struct {
	baseUrl     string
	client      *http.Client
	onDataFuncs []func(context.Context, *auth.AuthMessage) error
	mu          sync.Mutex
}

// SimplifiedHTTPTransportOptions represents configuration options for the transport
type SimplifiedHTTPTransportOptions struct {
	BaseURL string
	Client  *http.Client // Optional, if nil use default
}

// NewSimplifiedHTTPTransport creates a new HTTP transport instance
func NewSimplifiedHTTPTransport(options *SimplifiedHTTPTransportOptions) (*SimplifiedHTTPTransport, error) {
	if options.BaseURL == "" {
		return nil, errors.New("BaseURL is required for HTTP transport")
	}
	client := options.Client
	if client == nil {
		client = &http.Client{}
	}
	return &SimplifiedHTTPTransport{
		baseUrl: options.BaseURL,
		client:  client,
	}, nil
}

// OnData registers a callback for incoming messages
// This method will return an error only if the provided callback is nil.
// It must be called at least once before sending any messages.
func (t *SimplifiedHTTPTransport) OnData(callback func(context.Context, *auth.AuthMessage) error) error {
	if callback == nil {
		return errors.New("callback cannot be nil")
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.onDataFuncs = append(t.onDataFuncs, callback)
	return nil
}

// GetRegisteredOnData returns the first registered callback function for handling incoming AuthMessages.
// Returns an error if no handlers are registered.
func (t *SimplifiedHTTPTransport) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.onDataFuncs) == 0 {
		return nil, errors.New("no handlers registered")
	}

	// Return the first handler for simplicity
	return t.onDataFuncs[0], nil
}

// Send sends an AuthMessage via HTTP
func (t *SimplifiedHTTPTransport) Send(ctx context.Context, message *auth.AuthMessage) error {
	// Check if any handlers are registered
	t.mu.Lock()
	if len(t.onDataFuncs) == 0 {
		t.mu.Unlock()
		return ErrNoHandlerRegistered
	}
	t.mu.Unlock()

	if message.MessageType == auth.MessageTypeGeneral {
		return t.sendGeneralMessage(ctx, message)
	}
	return t.sendNonGeneralMessage(ctx, message)
}

func (t *SimplifiedHTTPTransport) sendNonGeneralMessage(ctx context.Context, message *auth.AuthMessage) error {
	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal auth message: %w", err)
	}

	requestURL := t.baseUrl
	if message.MessageType != auth.MessageTypeGeneral {
		requestURL = t.baseUrl + "/.well-known/auth"
	}

	resp, err := t.client.Post(requestURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	responseMsg, err := t.authMessageFromNonGeneralMessageResponse(resp)
	if err != nil {
		return fmt.Errorf("%s message to (%s | %s) failed: %w", message.MessageType, message.IdentityKey.ToDERHex(), requestURL, err)
	}

	return t.notifyHandlers(ctx, &responseMsg)
}

func (t *SimplifiedHTTPTransport) authMessageFromNonGeneralMessageResponse(resp *http.Response) (auth.AuthMessage, error) {
	var responseMsg auth.AuthMessage

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return responseMsg, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	if resp.ContentLength == 0 {
		return responseMsg, fmt.Errorf("empty response body")
	}

	// If we have a response, process it as a potential auth message
	if resp.ContentLength > 0 {

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return responseMsg, fmt.Errorf("failed to read response body: %w", err)
		}

		err = json.Unmarshal(body, &responseMsg)
		if err != nil {
			return responseMsg, fmt.Errorf("failed to unmarshal authmessage from body (%q): %w", string(body), err)
		}
	}
	return responseMsg, nil
}

func (t *SimplifiedHTTPTransport) sendGeneralMessage(ctx context.Context, message *auth.AuthMessage) error {
	// Step 1: Deserialize the payload into an HTTP request
	requestIDBytes, req, err := authpayload.ToHTTPRequest(message.Payload, authpayload.WithBaseURL(t.baseUrl))
	if err != nil {
		return fmt.Errorf("failed to deserialize request payload: %w", err)
	}

	requestID := base64.StdEncoding.EncodeToString(requestIDBytes)

	req.Header.Set(brc104.HeaderVersion, message.Version)
	req.Header.Set(brc104.HeaderIdentityKey, message.IdentityKey.ToDERHex())
	req.Header.Set(brc104.HeaderMessageType, string(message.MessageType))
	req.Header.Set(brc104.HeaderNonce, message.Nonce)
	req.Header.Set(brc104.HeaderYourNonce, message.YourNonce)
	req.Header.Set(brc104.HeaderSignature, hex.EncodeToString(message.Signature))
	req.Header.Set(brc104.HeaderRequestID, requestID)

	// Step 2: Perform the HTTP request
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to perform proxied HTTP request: %w", err)
	}
	defer resp.Body.Close()

	responseMsg, err := t.authMessageFromGeneralMessageResponse(requestIDBytes, resp)
	if err != nil {
		return err
	}

	return t.notifyHandlers(ctx, responseMsg)
}

func (t *SimplifiedHTTPTransport) authMessageFromGeneralMessageResponse(requestID []byte, res *http.Response) (*auth.AuthMessage, error) {
	version := res.Header.Get(brc104.HeaderVersion)
	if version == "" {
		return nil, errors.New("server failed to authenticate: missing version header in response")
	}

	responsePayload, err := authpayload.FromHTTPResponse(requestID, res)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize response to payload: %w", err)
	}

	messageType := res.Header.Get(brc104.HeaderMessageType)
	if messageType != "" && messageType != string(auth.MessageTypeGeneral) {
		return nil, fmt.Errorf("unexpectedly received non-general message type %s in response to general message", messageType)
	}

	identityKey := res.Header.Get(brc104.HeaderIdentityKey)
	if identityKey == "" {
		return nil, errors.New("missing identity key header in response")
	}
	pubKey, err := primitives.PublicKeyFromString(identityKey)
	if err != nil {
		return nil, fmt.Errorf("invalid identity key format in reponse: %w", err)
	}

	signature := res.Header.Get(brc104.HeaderSignature)
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature format in response: %w", err)
	}

	requestedCertificatesJson := res.Header.Get(brc104.HeaderRequestedCertificates)

	var requestedCertificates utils.RequestedCertificateSet
	if requestedCertificatesJson != "" {
		err = json.Unmarshal([]byte(requestedCertificatesJson), &requestedCertificates)
		if err != nil {
			return nil, fmt.Errorf("invalid format of requested certificates in response: %w", err)
		}
	}

	responseMsg := &auth.AuthMessage{
		Version:               version,
		MessageType:           auth.MessageTypeGeneral,
		IdentityKey:           pubKey,
		Nonce:                 res.Header.Get(brc104.HeaderNonce),
		YourNonce:             res.Header.Get(brc104.HeaderYourNonce),
		Signature:             sigBytes,
		RequestedCertificates: requestedCertificates,
		Payload:               responsePayload,
	}
	return responseMsg, nil
}

// notifyHandlers calls all registered callbacks with the received message
func (t *SimplifiedHTTPTransport) notifyHandlers(ctx context.Context, message *auth.AuthMessage) error {
	t.mu.Lock()
	handlers := make([]func(context.Context, *auth.AuthMessage) error, len(t.onDataFuncs))
	copy(handlers, t.onDataFuncs)
	t.mu.Unlock()

	for _, handler := range handlers {
		// Errors from handlers are not propagated to avoid breaking other handlers
		err := handler(ctx, message)
		if err != nil {
			return fmt.Errorf("failed to process %s message from peer: %w", message.MessageType, err)
		}
	}
	return nil
}
