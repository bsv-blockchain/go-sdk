package broadcaster

import (
	"net/http"
	"testing"
)

// roundTripFunc lets a plain function stand in for an http.RoundTripper so a
// test can feed canned responses to the process-global http.DefaultTransport
// that http.DefaultClient falls back to when a broadcaster is left with a nil
// Client.
type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip implements http.RoundTripper.
func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// withStubTransport swaps http.DefaultTransport for fn for the duration of the
// test and restores the previous transport via t.Cleanup. It lets a test drive
// the real nil-Client -> http.DefaultClient fallback path in the broadcasters
// without touching the network.
//
// Because it mutates a process-global, tests that call it MUST NOT call
// t.Parallel().
func withStubTransport(t *testing.T, fn roundTripFunc) {
	t.Helper()
	prev := http.DefaultTransport
	http.DefaultTransport = fn
	t.Cleanup(func() { http.DefaultTransport = prev })
}
