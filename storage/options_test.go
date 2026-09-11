package storage

import (
	"testing"

	"github.com/stretchr/testify/require"

	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
)

// The functional options document a non-nil contract by panicking on nil input.
// These tests lock in that behavior for every storage option.

func TestWithDownloaderClientNilPanics(t *testing.T) {
	t.Parallel()
	require.Panics(t, func() { WithDownloaderClient(nil) })
}

func TestWithDownloaderClientAcceptsClient(t *testing.T) {
	t.Parallel()
	require.NotPanics(t, func() { WithDownloaderClient(&tu.MockHTTPClient{}) })
}

func TestWithLookupResolverNilPanics(t *testing.T) {
	t.Parallel()
	require.Panics(t, func() { WithLookupResolver(nil) })
}

func TestWithUploaderClientNilPanics(t *testing.T) {
	t.Parallel()
	require.Panics(t, func() { WithUploaderClient(nil) })
}

func TestWithUploaderClientAcceptsClient(t *testing.T) {
	t.Parallel()
	require.NotPanics(t, func() { WithUploaderClient(&tu.MockHTTPClient{}) })
}

func TestWithAuthFetcherNilPanics(t *testing.T) {
	t.Parallel()
	require.Panics(t, func() { WithAuthFetcher(nil) })
}
