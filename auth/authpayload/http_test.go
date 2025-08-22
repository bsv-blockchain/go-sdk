package authpayload_test

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/auth/authpayload"
	"github.com/bsv-blockchain/go-sdk/auth/brc104"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/util"
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
			serializedPayload, err := authpayload.FromHTTPRequest(tc.requestID, tc.request)
			require.NoError(t, err)

			// and:
			requestID, req, err := authpayload.ToHTTPRequest(serializedPayload)

			// then:
			require.NoError(t, err)

			// and:
			assert.Equal(t, tc.requestID, requestID)

			// and:
			assert.Equal(t, tc.request.Method, req.Method)
			assert.Equal(t, tc.request.Header, req.Header)

			// and: match url
			expectedPath := tc.request.URL.Path
			if expectedPath == "" {
				// we need to do that change this is how go server will handle calls to empty path
				expectedPath = "/"
			}
			assert.Equal(t, expectedPath, req.URL.Path)
			assert.Equal(t, tc.request.URL.RawQuery, req.URL.RawQuery)

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

			assert.EqualValues(t, originalBody, deserializedBody)
		})
	}
}

func TestHTTPRequestPayloadSkippingHeaders(t *testing.T) {
	tests := map[string]struct {
		headerName string
	}{
		"skip x-bsv-auth-version header": {
			headerName: "x-bsv-auth-version",
		},
		"skip x-bsv-auth-message-type header": {
			headerName: "x-bsv-auth-message-type",
		},
		"skip x-bsv-auth-identity-key header": {
			headerName: "x-bsv-auth-identity-key",
		},
		"skip x-bsv-auth-your-nonce header": {
			headerName: "x-bsv-auth-your-nonce",
		},
		"skip x-bsv-auth-signature header": {
			headerName: "x-bsv-auth-signature",
		},
		"skip custom header": {
			headerName: "x-custom-header",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// given:
			requestID := bytes.Repeat([]byte{1}, 32)

			// and:
			request, err := http.NewRequest("GET", "https://example.com", nil)
			require.NoError(t, err, "failed to prepare request, invalid test setup")
			request.Header.Set(test.headerName, "value")

			// when:
			serializedPayload, err := authpayload.FromHTTPRequest(requestID, request)
			require.NoError(t, err)

			// and:
			_, req, err := authpayload.ToHTTPRequest(serializedPayload)
			require.NoError(t, err)

			// then:
			require.Empty(t, req.Header.Get(test.headerName))
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
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			serializedPayload, err := authpayload.FromHTTPRequest(tc.requestID, tc.request)
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
			requestID, req, err := authpayload.ToHTTPRequest(tc.payload)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.errMsg)
			assert.Nil(t, requestID)
			assert.Nil(t, req)
		})
	}
}

func TestHTTPResponsePayloadSuccessfulSerializationAndDeserialization(t *testing.T) {
	tests := map[string]struct {
		requestID []byte
		response  *http.Response
		body      []byte
		// expectedStatus is the expected value of http.Response.Status after deserialization
		expectedStatus string
	}{
		"200 OK with no headers and empty body": {
			requestID: bytes.Repeat([]byte{1}, 32),
			response: func() *http.Response {
				return &http.Response{
					StatusCode: 200,
					Header:     make(http.Header),
					Body:       io.NopCloser(bytes.NewReader(nil)),
				}
			}(),
			body:           []byte{},
			expectedStatus: "OK",
		},
		"response with headers (included only)": {
			requestID: bytes.Repeat([]byte{2}, 32),
			response: func() *http.Response {
				h := make(http.Header)
				h.Set("Authorization", "Bearer token123")
				h.Set("X-Bsv-Test", "test-value")
				return &http.Response{
					StatusCode: 200,
					Header:     h,
					Body:       io.NopCloser(bytes.NewReader([]byte("hello"))),
				}
			}(),
			body:           []byte("hello"),
			expectedStatus: "OK",
		},
		"404 Not Found with JSON body": {
			requestID: bytes.Repeat([]byte{3}, 32),
			response: func() *http.Response {
				return &http.Response{
					StatusCode: 404,
					Header:     make(http.Header),
					Body:       io.NopCloser(bytes.NewReader([]byte(`{"error":"not found"}`))),
				}
			}(),
			body:           []byte(`{"error":"not found"}`),
			expectedStatus: "Not Found",
		},
		"unknown 599 status code": {
			requestID: bytes.Repeat([]byte{4}, 32),
			response: func() *http.Response {
				return &http.Response{
					StatusCode: 599,
					Header:     make(http.Header),
					Body:       io.NopCloser(bytes.NewReader([]byte(""))),
				}
			}(),
			body:           []byte(""),
			expectedStatus: "599",
		},
		"binary body preserved": {
			requestID: bytes.Repeat([]byte{5}, 32),
			response: func() *http.Response {
				bin := []byte{0x00, 0x01, 0x02, 0xFF}
				return &http.Response{
					StatusCode: 201,
					Header:     make(http.Header),
					Body:       io.NopCloser(bytes.NewReader(bin)),
				}
			}(),
			body:           []byte{0x00, 0x01, 0x02, 0xFF},
			expectedStatus: "Created",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// when
			serializedPayload, err := authpayload.FromHTTPResponse(tc.requestID, tc.response)
			require.NoError(t, err)

			// and
			requestID, res, err := authpayload.ToHTTPResponse(serializedPayload)
			require.NoError(t, err)

			// then
			assert.Equal(t, tc.requestID, requestID)
			assert.Equal(t, tc.response.StatusCode, res.StatusCode)
			assert.Equal(t, tc.expectedStatus, res.Status)

			// headers equality only for included ones
			// In this test suite we used only included headers in input, so they should match exactly
			assert.Equal(t, tc.response.Header, res.Header)

			// body match
			var deserializedBody []byte
			if res.Body != nil {
				deserializedBody, err = io.ReadAll(res.Body)
				require.NoError(t, err, "failed to read deserialized body")
			}
			assert.Equal(t, tc.body, deserializedBody)
		})
	}
}

func TestHTTPResponsePayloadSkippingHeaders(t *testing.T) {
	tests := map[string]struct{ headerName string }{
		"skip x-bsv-auth-version header":       {headerName: "x-bsv-auth-version"},
		"skip x-bsv-auth-message-type header":  {headerName: "x-bsv-auth-message-type"},
		"skip x-bsv-auth-identity-key header":  {headerName: "x-bsv-auth-identity-key"},
		"skip x-bsv-auth-your-nonce header":    {headerName: "x-bsv-auth-your-nonce"},
		"skip x-bsv-auth-signature header":     {headerName: "x-bsv-auth-signature"},
		"skip content-type header (responses)": {headerName: "content-type"},
		"skip custom header":                   {headerName: "x-custom-header"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			requestID := bytes.Repeat([]byte{9}, 32)
			res := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader(nil)),
			}
			res.Header.Set(test.headerName, "value")

			serializedPayload, err := authpayload.FromHTTPResponse(requestID, res)
			require.NoError(t, err)

			_, outRes, err := authpayload.ToHTTPResponse(serializedPayload)
			require.NoError(t, err)

			require.Empty(t, outRes.Header.Get(test.headerName))
		})
	}
}

func TestHTTPResponsePayloadSerializationAndDeserializationErrors(t *testing.T) {
	serializationTests := map[string]struct {
		requestID []byte
		response  *http.Response
		errMsg    string
	}{
		"Error when serialize with empty request ID": {
			requestID: nil,
			response: &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader(nil)),
			},
			errMsg: "request ID",
		},
		"Error when serialize with too long request ID": {
			requestID: bytes.Repeat([]byte{1}, 33),
			response: &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader(nil)),
			},
			errMsg: "request ID",
		},
		"Error when serialize with too short request ID": {
			requestID: bytes.Repeat([]byte{2}, 31),
			response: &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader(nil)),
			},
			errMsg: "request ID",
		},
		"Error when serialize with multiple values for header": {
			requestID: bytes.Repeat([]byte{4}, 32),
			response: func() *http.Response {
				h := make(http.Header)
				h.Add("X-Bsv-Test", "value1")
				h.Add("X-Bsv-Test", "value2")
				return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(bytes.NewReader(nil))}
			}(),
			errMsg: "multiple values for header",
		},
	}

	for name, tc := range serializationTests {
		t.Run(name, func(t *testing.T) {
			serializedPayload, err := authpayload.FromHTTPResponse(tc.requestID, tc.response)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.errMsg)
			assert.Nil(t, serializedPayload)
		})
	}

	deserializationTests := map[string]struct {
		payload []byte
		errMsg  string
	}{
		"Error when deserialize empty payload": {
			payload: []byte{},
			errMsg:  "failed to read response to create http response",
		},
		"Error when deserialize too short request ID": {
			payload: bytes.Repeat([]byte{1}, 16), // 16 bytes only
			errMsg:  "failed to read response to create http response",
		},
		"Error when truncated before headers count": {
			payload: func() []byte {
				w := util.NewWriter()
				w.WriteBytes(bytes.Repeat([]byte{7}, 32)) // requestID
				w.WriteVarInt(uint64(200))                // status code
				// do not write headers count -> triggers error when reading header count
				return w.Buf
			}(),
			errMsg: "failed to read header count to create http response",
		},
	}
	for name, tc := range deserializationTests {
		t.Run(name, func(t *testing.T) {
			requestID, res, err := authpayload.ToHTTPResponse(tc.payload)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.errMsg)
			assert.Nil(t, requestID)
			assert.Nil(t, res)
		})
	}
}

func TestToHTTPResponseInjectsSenderPublicKeyHeader(t *testing.T) {
	// given
	requestID := bytes.Repeat([]byte{8}, 32)
	h := make(http.Header)
	h.Set("X-Bsv-Test", "yes")
	res := &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(bytes.NewReader(nil))}

	// and: serialize without identity key
	payload, err := authpayload.FromHTTPResponse(requestID, res)
	require.NoError(t, err)

	// and: prepare sender public key
	priv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	senderPub := priv.PubKey()

	// when: deserialize with option
	_, outRes, err := authpayload.ToHTTPResponse(payload, authpayload.WithSenderPublicKey(senderPub))
	require.NoError(t, err)

	// then: header is injected
	assert.Equal(t, senderPub.ToDERHex(), outRes.Header.Get(brc104.HeaderIdentityKey))
}
