package identity

import (
	"errors"
	"net/http"
	"testing"
)

// roundTripFunc lets a plain function stand in for an http.RoundTripper so a
// test can intercept the process-global http.DefaultTransport that the overlay
// broadcaster's default HTTP client (topic broadcaster + lookup resolver) falls
// back to.
type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip implements http.RoundTripper.
func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// withStubTransport swaps http.DefaultTransport for fn for the duration of the
// test and restores it via t.Cleanup. It lets the identity reveal-attributes
// tests exercise the GetNetwork -> broadcaster code path without any real
// DNS/HTTP to overlay hosts.
//
// Because it mutates a process-global, tests that call it MUST NOT call
// t.Parallel().
func withStubTransport(t *testing.T, fn roundTripFunc) {
	t.Helper()
	prev := http.DefaultTransport
	http.DefaultTransport = fn
	t.Cleanup(func() { http.DefaultTransport = prev })
}

// stubTransportUnreachable returns a transport that fails every request
// immediately, standing in for "no overlay host reachable" without waiting on
// real network timeouts.
func stubTransportUnreachable(t *testing.T) {
	t.Helper()
	withStubTransport(t, func(_ *http.Request) (*http.Response, error) {
		return nil, errors.New("network disabled in unit tests")
	})
}
