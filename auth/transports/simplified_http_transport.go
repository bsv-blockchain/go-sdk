package transports

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/payload"
	"github.com/bsv-blockchain/go-sdk/util"
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
	_, req, err := payload.ToHTTPRequest(message.Payload, payload.WithBaseURL(t.baseUrl))
	if err != nil {
		return fmt.Errorf("failed to deserialize request payload: %w", err)
	}

	// Step 2: Perform the HTTP request
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to perform proxied HTTP request: %w", err)
	}
	defer resp.Body.Close()

	responseMsg, err := t.authMessageFromGeneralMessageResponse(message.Version, resp)
	if err != nil {
		return err
	}

	return t.notifyHandlers(ctx, responseMsg)
}

func (t *SimplifiedHTTPTransport) authMessageFromGeneralMessageResponse(version string, resp *http.Response) (*auth.AuthMessage, error) {
	// Step 3: Serialize the response as an AuthMessage and notify handlers
	respPayloadWriter := util.NewWriter()
	respPayloadWriter.WriteVarInt(uint64(resp.StatusCode))
	// Write headers (count, then key/value pairs)
	headers := resp.Header
	headersList := make([][2]string, 0)
	for k, vs := range headers {
		for _, v := range vs {
			headersList = append(headersList, [2]string{k, v})
		}
	}
	respPayloadWriter.WriteVarInt(uint64(len(headersList)))
	for _, kv := range headersList {
		respPayloadWriter.WriteString(kv[0])
		respPayloadWriter.WriteString(kv[1])
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read proxied response body: %w", err)
	}
	respPayloadWriter.WriteVarInt(uint64(len(respBody)))
	respPayloadWriter.WriteBytes(respBody)

	responseMsg := &auth.AuthMessage{
		Version:     version,
		MessageType: auth.MessageTypeGeneral,
		Payload:     respPayloadWriter.Buf,
	}
	return responseMsg, nil
}

// deserializeRequestPayload parses the payload into an HTTP request and requestId (basic implementation)
func (t *SimplifiedHTTPTransport) deserializeRequestPayload(payload []byte) (*http.Request, string, error) {
	// This is a minimal implementation for alignment and test unblocking
	if len(payload) < 32 {
		return nil, "", errors.New("payload too short for requestId")
	}
	requestId := payload[:32] // first 32 bytes is requestId (as in TS)
	reader := bytes.NewReader(payload[32:])

	// Helper to read a varint (as in TS)
	readVarInt := func() (int, error) {
		var b [1]byte
		if _, err := reader.Read(b[:]); err != nil {
			return 0, err
		}
		return int(b[0]), nil // Only support 1-byte varint for now
	}

	// Method
	methodLen, err := readVarInt()
	if err != nil {
		return nil, "", err
	}
	method := "GET"
	if methodLen > 0 {
		m := make([]byte, methodLen)
		if _, err := io.ReadFull(reader, m); err != nil {
			return nil, "", err
		}
		method = string(m)
	}

	// Path
	pathLen, err := readVarInt()
	if err != nil {
		return nil, "", err
	}
	path := ""
	if pathLen > 0 {
		p := make([]byte, pathLen)
		if _, err := io.ReadFull(reader, p); err != nil {
			return nil, "", err
		}
		path = string(p)
	}

	// Search
	searchLen, err := readVarInt()
	if err != nil {
		return nil, "", err
	}
	search := ""
	if searchLen > 0 {
		s := make([]byte, searchLen)
		if _, err = io.ReadFull(reader, s); err != nil {
			return nil, "", err
		}
		search = string(s)
	}

	// Headers
	headers := http.Header{}
	nHeaders, err := readVarInt()
	if err != nil {
		return nil, "", err
	}
	for i := 0; i < nHeaders; i++ {
		keyLen, err := readVarInt()
		if err != nil {
			return nil, "", err
		}
		key := make([]byte, keyLen)
		if _, err := io.ReadFull(reader, key); err != nil {
			return nil, "", err
		}
		valLen, err := readVarInt()
		if err != nil {
			return nil, "", err
		}
		val := make([]byte, valLen)
		if _, err := io.ReadFull(reader, val); err != nil {
			return nil, "", err
		}
		headers.Add(string(key), string(val))
	}

	// Body
	bodyLen, err := readVarInt()
	if err != nil {
		return nil, "", err
	}
	var body []byte
	if bodyLen > 0 {
		body = make([]byte, bodyLen)
		if _, err := io.ReadFull(reader, body); err != nil {
			return nil, "", err
		}
	}

	// Build the URL
	urlStr := t.baseUrl + path + search
	parsedUrl, err := url.Parse(urlStr)
	if err != nil {
		return nil, "", err
	}

	// Build the request
	req, err := http.NewRequest(method, parsedUrl.String(), bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	req.Header = headers

	return req, string(requestId), nil
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
