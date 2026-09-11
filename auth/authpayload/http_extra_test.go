package authpayload_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/auth/authpayload"
	"github.com/bsv-blockchain/go-sdk/util"
)

// errReadCloser is an io.ReadCloser whose Read always fails, used to exercise
// body-read error branches.
type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, errors.New("boom read") }

func (errReadCloser) Close() error { return nil }

func TestToHTTPRequestWithBaseURL(t *testing.T) {
	// given: a serialized request with a path and query params
	requestID := bytes.Repeat([]byte{1}, 32)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://ignored/api/resource?x=1", nil)
	require.NoError(t, err)

	payload, err := authpayload.FromHTTPRequest(requestID, req)
	require.NoError(t, err)

	// when: deserializing with a base URL option
	const baseURL = "https://base.example.com"
	gotID, gotReq, err := authpayload.ToHTTPRequest(payload, authpayload.WithBaseURL(baseURL))

	// then:
	require.NoError(t, err)
	assert.Equal(t, requestID, gotID)
	assert.Equal(t, "base.example.com", gotReq.URL.Host)
	assert.Equal(t, "https", gotReq.URL.Scheme)
	assert.Equal(t, "/api/resource", gotReq.URL.Path)
	assert.Equal(t, "x=1", gotReq.URL.RawQuery)
}

func TestToHTTPRequestDeserializationErrorBranches(t *testing.T) {
	requestID := bytes.Repeat([]byte{7}, 32)

	tests := map[string]struct {
		payload []byte
		errMsg  string
	}{
		"error reading method": {
			payload: func() []byte {
				w := util.NewWriter()
				w.WriteBytes(requestID)
				return w.Buf
			}(),
			errMsg: "failed to read method from payload",
		},
		"error reading path": {
			payload: func() []byte {
				w := util.NewWriter()
				w.WriteBytes(requestID)
				w.WriteString(http.MethodGet)
				return w.Buf
			}(),
			errMsg: "failed to read path from payload",
		},
		"error reading search params": {
			payload: func() []byte {
				w := util.NewWriter()
				w.WriteBytes(requestID)
				w.WriteString(http.MethodGet)
				w.WriteString("/api")
				return w.Buf
			}(),
			errMsg: "failed to read search params from payload",
		},
		"error creating url from invalid escape": {
			payload: func() []byte {
				w := util.NewWriter()
				w.WriteBytes(requestID)
				w.WriteString(http.MethodGet)
				w.WriteString("%zz") // invalid percent-escape -> url.Parse fails
				w.WriteOptionalString("")
				return w.Buf
			}(),
			errMsg: "failed to create url from payload",
		},
		"error reading number of headers": {
			payload: func() []byte {
				w := util.NewWriter()
				w.WriteBytes(requestID)
				w.WriteString(http.MethodGet)
				w.WriteString("/api")
				w.WriteOptionalString("")
				return w.Buf
			}(),
			errMsg: "failed to read number of headers",
		},
		"error reading header name": {
			payload: func() []byte {
				w := util.NewWriter()
				w.WriteBytes(requestID)
				w.WriteString(http.MethodGet)
				w.WriteString("/api")
				w.WriteOptionalString("")
				w.WriteVarInt(1) // claim one header but write nothing
				return w.Buf
			}(),
			errMsg: "name from payload",
		},
		"error reading header value": {
			payload: func() []byte {
				w := util.NewWriter()
				w.WriteBytes(requestID)
				w.WriteString(http.MethodGet)
				w.WriteString("/api")
				w.WriteOptionalString("")
				w.WriteVarInt(1)
				w.WriteString("x-bsv-test") // header name but no value
				return w.Buf
			}(),
			errMsg: "value from payload",
		},
		"error reading body": {
			payload: func() []byte {
				w := util.NewWriter()
				w.WriteBytes(requestID)
				w.WriteString(http.MethodGet)
				w.WriteString("/api")
				w.WriteOptionalString("")
				w.WriteVarInt(0) // no headers, then no body bytes
				return w.Buf
			}(),
			errMsg: "failed to read body from payload",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotID, gotReq, err := authpayload.ToHTTPRequest(tc.payload)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errMsg)
			assert.Nil(t, gotID)
			assert.Nil(t, gotReq)
		})
	}
}

func TestFromHTTPRequestBodyReadError(t *testing.T) {
	requestID := bytes.Repeat([]byte{1}, 32)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.com/api", nil)
	require.NoError(t, err)
	req.Body = errReadCloser{}

	payload, err := authpayload.FromHTTPRequest(requestID, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to read request body")
	assert.Nil(t, payload)
}

func TestFromHTTPResponseBodyReadError(t *testing.T) {
	requestID := bytes.Repeat([]byte{1}, 32)
	res := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       errReadCloser{},
	}

	payload, err := authpayload.FromHTTPResponse(requestID, res)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to read response body")
	assert.Nil(t, payload)
}

func TestToSimplifiedHTTPResponseErrorBranches(t *testing.T) {
	requestID := bytes.Repeat([]byte{5}, 32)

	tests := map[string]struct {
		payload []byte
		errMsg  string
	}{
		"error reading status code": {
			payload: func() []byte {
				w := util.NewWriter()
				w.WriteBytes(requestID)
				return w.Buf
			}(),
			errMsg: "failed to read status code",
		},
		"error reading header key": {
			payload: func() []byte {
				w := util.NewWriter()
				w.WriteBytes(requestID)
				w.WriteVarInt(uint64(http.StatusOK))
				w.WriteVarInt(1) // one header but no key
				return w.Buf
			}(),
			errMsg: "key to create http response",
		},
		"error reading header value": {
			payload: func() []byte {
				w := util.NewWriter()
				w.WriteBytes(requestID)
				w.WriteVarInt(uint64(http.StatusOK))
				w.WriteVarInt(1)
				w.WriteString("x-bsv-test") // key present but no value
				return w.Buf
			}(),
			errMsg: "value to create http response",
		},
		"error reading body": {
			payload: func() []byte {
				w := util.NewWriter()
				w.WriteBytes(requestID)
				w.WriteVarInt(uint64(http.StatusOK))
				w.WriteVarInt(0) // no headers, then no body bytes
				return w.Buf
			}(),
			errMsg: "failed to read body",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotID, res, err := authpayload.ToSimplifiedHttpResponse(tc.payload)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errMsg)
			assert.Nil(t, gotID)
			assert.Empty(t, res.Body)
		})
	}
}
