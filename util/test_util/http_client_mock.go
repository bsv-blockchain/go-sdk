package tu

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// MockHTTPClient is a socket-free implementation of util.HTTPClient (a type with
// a Do(*http.Request) (*http.Response, error) method). It records every request
// it receives so tests can assert on the outgoing URL, method, headers, and body,
// and it returns whatever DoFunc produces. Because it performs no real I/O, tests
// using it need no httptest server and are safe to run with t.Parallel().
type MockHTTPClient struct {
	// DoFunc produces the response (or error) for each call. If nil, Do returns a
	// 200 response with an empty body.
	DoFunc func(*http.Request) (*http.Response, error)

	// Requests records every request passed to Do, in call order, for assertions.
	Requests []*http.Request
}

// Do records req and delegates to DoFunc. It satisfies util.HTTPClient.
func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.Requests = append(m.Requests, req)
	if m.DoFunc == nil {
		return StringResponse(http.StatusOK, ""), nil
	}
	return m.DoFunc(req)
}

// LastRequest returns the most recently recorded request, or nil if Do was never
// called.
func (m *MockHTTPClient) LastRequest() *http.Request {
	if len(m.Requests) == 0 {
		return nil
	}
	return m.Requests[len(m.Requests)-1]
}

// JSONResponse builds an *http.Response with the given status code whose body is
// the JSON encoding of v and whose Content-Type is application/json. It fails the
// test if v cannot be marshaled.
func JSONResponse(t testing.TB, status int, v any) *http.Response {
	t.Helper()
	body, err := json.Marshal(v)
	require.NoError(t, err)
	resp := StringResponse(status, string(body))
	resp.Header.Set("Content-Type", "application/json")
	return resp
}

// StringResponse builds an *http.Response with the given status code and body. The
// Header is initialized so callers can set additional headers, and Body is a
// NopCloser so callers do not have to close it (though closing is harmless).
func StringResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

// ErrorResponder returns a DoFunc that always fails with err, standing in for a
// transport-level failure (DNS, connection refused, timeout) without any real
// network. Assign it to MockHTTPClient.DoFunc to exercise the Do-error branch of
// a caller.
func ErrorResponder(err error) func(*http.Request) (*http.Response, error) {
	return func(*http.Request) (*http.Response, error) {
		return nil, err
	}
}
