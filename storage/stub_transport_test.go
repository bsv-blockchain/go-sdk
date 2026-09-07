package storage

import (
	"errors"
	"net/http"
	"testing"
)

// roundTripFunc lets a plain function stand in for an http.RoundTripper so a
// test can intercept the process-global http.DefaultTransport that the
// uploader's authenticated HTTP client (authhttp.New defaults to &http.Client{})
// falls back to.
type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip implements http.RoundTripper.
func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// withStubTransport swaps http.DefaultTransport for fn for the duration of the
// test and restores it via t.Cleanup.
//
// Because it mutates a process-global, tests that call it MUST NOT call
// t.Parallel().
func withStubTransport(t *testing.T, fn roundTripFunc) {
	t.Helper()
	prev := http.DefaultTransport
	http.DefaultTransport = fn
	t.Cleanup(func() { http.DefaultTransport = prev })
}

// stubTransportUnreachable makes every request fail immediately, standing in for
// "no storage server reachable" so the uploader's auth calls return a transport
// error instead of doing real DNS/HTTP to the configured StorageURL.
func stubTransportUnreachable(t *testing.T) {
	t.Helper()
	withStubTransport(t, func(_ *http.Request) (*http.Response, error) {
		return nil, errors.New("network disabled in unit tests")
	})
}
