package payload_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/auth/payload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPRequestPayloadSuccessfulSerializationAndDeserialization(t *testing.T) {
	tests := map[string]struct {
		requestID []byte
		request   *http.Request
	}{
		"GET from root path": {
			requestID: bytes.Repeat([]byte{1}, 32),
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com", nil)
				return req
			}(),
		},
		"request with path": {
			requestID: bytes.Repeat([]byte{2}, 32),
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com/api/resource/123", nil)
				return req
			}(),
		},
		"request with query params": {
			requestID: bytes.Repeat([]byte{3}, 32),
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com?param1=value1&param2=value2", nil)
				return req
			}(),
		},
		"request with path and query params": {
			requestID: bytes.Repeat([]byte{3}, 32),
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com?param1=value1&param2=value2", nil)
				return req
			}(),
		},
		"POST request with JSON body": {
			requestID: bytes.Repeat([]byte{4}, 32),
			request: func() *http.Request {
				body := strings.NewReader(`{"key":"value"}`)
				req, _ := http.NewRequest("POST", "https://example.com/api/resource", body)
				req.Header.Set("Content-Type", "application/json")
				return req
			}(),
		},
		"POST request with empty JSON body": {
			requestID: bytes.Repeat([]byte{5}, 32),
			request: func() *http.Request {
				req, _ := http.NewRequest("POST", "https://example.com/api/resource", nil)
				req.Header.Set("Content-Type", "application/json")
				return req
			}(),
		},
		"POST request with non-JSON body": {
			requestID: bytes.Repeat([]byte{6}, 32),
			request: func() *http.Request {
				body := strings.NewReader(`plain text content`)
				req, _ := http.NewRequest("POST", "https://example.com/api/resource", body)
				return req
			}(),
		},
		"Request with headers": {
			requestID: bytes.Repeat([]byte{7}, 32),
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com/api/resource", nil)
				req.Header.Set("Authorization", "Bearer token123")
				req.Header.Set("X-Bsv-Test", "test-value")
				return req
			}(),
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// when
			serializedPayload, err := payload.FromHTTPRequest(tc.requestID, tc.request)
			require.NoError(t, err)

			fmt.Printf("%v", serializedPayload)

			// and:
			requestID, req, err := payload.ToHTTPRequest(serializedPayload)

			// then:
			require.NoError(t, err)

			// and:
			assert.Equal(t, tc.requestID, requestID)

			// and:
			assert.Equal(t, tc.request.Method, req.Method)
			assert.Equal(t, tc.request.URL.Path, req.URL.Path)
			assert.Equal(t, tc.request.URL.RawQuery, req.URL.RawQuery)
			assert.Equal(t, tc.request.Header, req.Header)

			// and: body match
			var originalBody []byte
			if tc.request.Body != nil {
				originalBody, err = io.ReadAll(tc.request.Body)
				require.NoError(t, err, "failed to read expected body")
			}

			var deserializedBody []byte
			if req.Body != nil {
				deserializedBody, err = io.ReadAll(req.Body)
				require.NoError(t, err, "failed to read deserialized body")
			}

			assert.Equal(t, originalBody, deserializedBody)
		})
	}
}

func TestHTTPRequestPayloadSerializationAndDeserializationErrors(t *testing.T) {
	tests := map[string]struct {
		requestID []byte
		request   *http.Request
		errMsg    string
	}{
		"Error when serialize with empty request ID": {
			requestID: nil,
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com/api/resource", nil)
				return req
			}(),
			errMsg: "request ID must be 32 bytes long",
		},
		"Error when serialize with too long request ID": {
			requestID: bytes.Repeat([]byte{1}, 33),
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com/api/resource", nil)
				return req
			}(),
			errMsg: "request ID must be 32 bytes long",
		},
		"Error when serialize with too short request ID": {
			requestID: bytes.Repeat([]byte{2}, 31),
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com/api/resource", nil)
				return req
			}(),
			errMsg: "request ID must be 32 bytes long",
		},
		"Error when serialize with x-bsv-auth header": {
			requestID: bytes.Repeat([]byte{3}, 32),
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com/api/resource", nil)
				req.Header.Set("X-Bsv-Auth", "some-value")
				return req
			}(),
			errMsg: "request with x-bsv-auth cannot be serialized",
		},
		"Error when serialize with multiple values for header": {
			requestID: bytes.Repeat([]byte{4}, 32),
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com/api/resource", nil)
				req.Header.Add("X-Bsv-Test", "value1")
				req.Header.Add("X-Bsv-Test", "value2")
				return req
			}(),
			errMsg: "multiple values for header",
		},
		"Error when serialize with multiple values for content-type": {
			requestID: bytes.Repeat([]byte{5}, 32),
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com/api/resource", nil)
				req.Header.Add("Content-Type", "application/json")
				req.Header.Add("Content-Type", "text/plain")
				return req
			}(),
			errMsg: "multiple values for header",
		},
		"Error when serialize with unsupported header": {
			requestID: bytes.Repeat([]byte{6}, 32),
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com/api/resource", nil)
				req.Header.Set("Unsupported-Header", "value")
				return req
			}(),
			errMsg: "header unsupported-header is not supported by authrite",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			serializedPayload, err := payload.FromHTTPRequest(tc.requestID, tc.request)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.errMsg)
			assert.Nil(t, serializedPayload)
		})
	}

	deserializationTests := map[string]struct {
		payload []byte
		baseURL string
		errMsg  string
	}{
		"Error when deserialize empty payload": {
			payload: []byte{},
			baseURL: "",
			errMsg:  "failed to read request ID from payload",
		},
		"Error when deserialize too short request ID": {
			payload: []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, // Only 16 bytes
			baseURL: "",
			errMsg:  "failed to read request ID from payload",
		},
	}
	for name, tc := range deserializationTests {
		t.Run(name, func(t *testing.T) {
			requestID, req, err := payload.ToHTTPRequest(tc.payload)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.errMsg)
			assert.Nil(t, requestID)
			assert.Nil(t, req)
		})
	}
}
