package headers_client

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
)

// TestHeadersClientTransportErrors covers the client.Do error branch of every
// request method by injecting a mock HTTP client that always fails at the
// transport level.
func TestHeadersClientTransportErrors(t *testing.T) {
	t.Parallel()

	mock := &tu.MockHTTPClient{
		//nolint:bodyclose // ErrorResponder always returns (nil, err); there is no response body to close
		DoFunc: tu.ErrorResponder(errors.New("transport failure")),
	}
	requireAllRequestMethodsError(t, &Client{
		Url:        "https://headers.test",
		ApiKey:     testAPIKey,
		httpClient: mock,
	})
}

// TestHeadersClientRequestCreationErrors covers the "error creating request"
// branch by using a URL containing a control character that http.NewRequest
// rejects. This fails before any Do call, so the injected mock is never invoked.
func TestHeadersClientRequestCreationErrors(t *testing.T) {
	t.Parallel()

	requireAllRequestMethodsError(t, &Client{
		Url:        "http://headers.test/\x7f",
		ApiKey:     testAPIKey,
		httpClient: &tu.MockHTTPClient{},
	})
}

// requireAllRequestMethodsError asserts that every request-issuing method on c
// returns an error, so both the transport-failure and request-creation-failure
// cases can share one assertion set.
func requireAllRequestMethodsError(t *testing.T, c *Client) {
	t.Helper()
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
