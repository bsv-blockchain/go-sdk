package authhttp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// PeerInterface defines the interface required by the AuthHTTP client
type PeerInterface interface {
	ToPeer(message []byte, identityKey string, maxWaitTimeMs int) error
}

// Client provides HTTP functionality with built-in authentication
type Client struct {
	baseURL        string
	peer           PeerInterface
	client         *http.Client
	maxWaitTime    int
	defaultHeaders map[string]string
}

// Options contains configuration options for the AuthHTTP client
type Options struct {
	// Base URL for all requests
	BaseURL string

	// Peer instance for authentication
	Peer PeerInterface

	// Maximum time to wait for authentication (defaults to 10000ms)
	MaxWaitTime int

	// Custom HTTP client (optional)
	Client *http.Client

	// Default headers to include with every request
	DefaultHeaders map[string]string

	// Server's identity key (public key) for authentication
	ServerIdentityKey string
}

// New creates a new authenticated HTTP client
func New(options Options) (*Client, error) {
	if options.BaseURL == "" {
		return nil, fmt.Errorf("baseURL is required")
	}
	if options.Peer == nil {
		return nil, fmt.Errorf("peer is required")
	}

	client := options.Client
	if client == nil {
		client = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	maxWaitTime := 10000 // Default 10 seconds
	if options.MaxWaitTime > 0 {
		maxWaitTime = options.MaxWaitTime
	}

	defaultHeaders := options.DefaultHeaders
	if defaultHeaders == nil {
		defaultHeaders = make(map[string]string)
	}

	return &Client{
		baseURL:        options.BaseURL,
		peer:           options.Peer,
		client:         client,
		maxWaitTime:    maxWaitTime,
		defaultHeaders: defaultHeaders,
	}, nil
}

// RequestOptions contains options for a single request
type RequestOptions struct {
	// Additional headers specific to this request
	Headers map[string]string

	// Server identity key override for this request
	ServerIdentityKey string

	// Query parameters to append to the URL
	QueryParams map[string]string
}

// Request sends an authenticated request to the server
func (a *Client) Request(method, path string, body any, serverIdentityKey string, options *RequestOptions) (*http.Response, error) {
	var bodyReader io.Reader
	var bodyBytes []byte

	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewBuffer(bodyBytes)
	}

	// Parse the base URL
	baseURL, err := url.Parse(a.baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid baseURL: %w", err)
	}

	// Resolve the path against the base URL
	if path != "" {
		baseURL.Path = baseURL.ResolveReference(&url.URL{Path: path}).Path
	}

	// Add query parameters if provided
	if options != nil && len(options.QueryParams) > 0 {
		q := baseURL.Query()
		for key, value := range options.QueryParams {
			q.Add(key, value)
		}
		baseURL.RawQuery = q.Encode()
	}

	// Create the request with the fully constructed URL
	req, err := http.NewRequest(method, baseURL.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set default headers
	for k, v := range a.defaultHeaders {
		req.Header.Set(k, v)
	}

	// Set request-specific headers
	if options != nil && len(options.Headers) > 0 {
		for k, v := range options.Headers {
			req.Header.Set(k, v)
		}
	}

	// Set content type for JSON bodies
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Use peer to authenticate the request
	// We'll use the URL + body as the payload to authenticate
	authPayload := []byte(req.URL.String())
	if bodyBytes != nil {
		authPayload = append(authPayload, bodyBytes...)
	}

	// Use the provided identity key or the default one
	identityKey := serverIdentityKey
	if options != nil && options.ServerIdentityKey != "" {
		identityKey = options.ServerIdentityKey
	}

	err = a.peer.ToPeer(authPayload, identityKey, a.maxWaitTime)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Execute the request
	return a.client.Do(req)
}

// Get sends an authenticated GET request
func (a *Client) Get(path string, serverIdentityKey string, options *RequestOptions) (*http.Response, error) {
	return a.Request(http.MethodGet, path, nil, serverIdentityKey, options)
}

// Post sends an authenticated POST request
func (a *Client) Post(path string, body any, serverIdentityKey string, options *RequestOptions) (*http.Response, error) {
	return a.Request(http.MethodPost, path, body, serverIdentityKey, options)
}

// Put sends an authenticated PUT request
func (a *Client) Put(path string, body any, serverIdentityKey string, options *RequestOptions) (*http.Response, error) {
	return a.Request(http.MethodPut, path, body, serverIdentityKey, options)
}

// Delete sends an authenticated DELETE request
func (a *Client) Delete(path string, serverIdentityKey string, options *RequestOptions) (*http.Response, error) {
	return a.Request(http.MethodDelete, path, nil, serverIdentityKey, options)
}

// Patch sends an authenticated PATCH request
func (a *Client) Patch(path string, body any, serverIdentityKey string, options *RequestOptions) (*http.Response, error) {
	return a.Request(http.MethodPatch, path, body, serverIdentityKey, options)
}

// GetJSON sends an authenticated GET request and unmarshals the JSON response
func (a *Client) GetJSON(path string, serverIdentityKey string, options *RequestOptions, target any) error {
	resp, err := a.Get(path, serverIdentityKey, options)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return json.NewDecoder(resp.Body).Decode(target)
}

// PostJSON sends an authenticated POST request and unmarshals the JSON response
func (a *Client) PostJSON(path string, body any, serverIdentityKey string, options *RequestOptions, target any) error {
	resp, err := a.Post(path, body, serverIdentityKey, options)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return json.NewDecoder(resp.Body).Decode(target)
}
