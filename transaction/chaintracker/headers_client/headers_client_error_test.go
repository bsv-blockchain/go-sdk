package headers_client

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
)

// errRoundTripper fails every request, standing in for a transport-level
// network error without any real DNS/HTTP.
type errRoundTripper struct{}

func (errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("transport failure")
}

// withErrTransport swaps http.DefaultTransport (used by the inline &http.Client{}
// and getHTTPClient() fallbacks) for one that always errors, and restores it via
// t.Cleanup. It must not be used with t.Parallel().
func withErrTransport(t *testing.T) {
	t.Helper()
	prev := http.DefaultTransport
	http.DefaultTransport = errRoundTripper{}
	t.Cleanup(func() { http.DefaultTransport = prev })
}

// TestHeadersClientTransportErrors covers the client.Do error branch of every
// request method by making the transport fail.
func TestHeadersClientTransportErrors(t *testing.T) {
	withErrTransport(t)

	c := &Client{Url: "http://headers.test", ApiKey: testAPIKey}
	ctx := context.Background()
	root := &chainhash.Hash{}

	_, err := c.IsValidRootForHeight(ctx, root, 1)
	require.Error(t, err)

	_, err = c.BlockByHeight(ctx, 1)
	require.Error(t, err)

	_, err = c.GetBlockState(ctx, "deadbeef")
	require.Error(t, err)

	_, err = c.GetChaintip(ctx)
	require.Error(t, err)

	_, err = c.CurrentHeight(ctx)
	require.Error(t, err)

	_, err = c.GetMerkleRoots(ctx, 10, nil)
	require.Error(t, err)

	_, err = c.RegisterWebhook(ctx, "https://example.com/webhook", "tok")
	require.Error(t, err)

	err = c.UnregisterWebhook(ctx, "https://example.com/webhook")
	require.Error(t, err)

	_, err = c.GetWebhook(ctx, "https://example.com/webhook")
	require.Error(t, err)
}

// TestHeadersClientRequestCreationErrors covers the "error creating request"
// branch by using a URL containing a control character that http.NewRequest
// rejects.
func TestHeadersClientRequestCreationErrors(t *testing.T) {
	c := &Client{Url: "http://headers.test/\x7f", ApiKey: testAPIKey}
	ctx := context.Background()
	root := &chainhash.Hash{}

	_, err := c.IsValidRootForHeight(ctx, root, 1)
	require.Error(t, err)

	_, err = c.BlockByHeight(ctx, 1)
	require.Error(t, err)

	_, err = c.GetBlockState(ctx, "deadbeef")
	require.Error(t, err)

	_, err = c.GetChaintip(ctx)
	require.Error(t, err)

	_, err = c.GetMerkleRoots(ctx, 10, nil)
	require.Error(t, err)

	_, err = c.RegisterWebhook(ctx, "https://example.com/webhook", "tok")
	require.Error(t, err)

	err = c.UnregisterWebhook(ctx, "https://example.com/webhook")
	require.Error(t, err)

	_, err = c.GetWebhook(ctx, "https://example.com/webhook")
	require.Error(t, err)
}
