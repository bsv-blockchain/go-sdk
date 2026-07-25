package clients

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/wallet"
)

// TestFetchConcurrentRequestsAllResolve is a regression test for the response
// listener deregistering itself BEFORE the nonce-match check: because
// Peer.handleGeneralMessage fans each received message out to every registered
// listener, the first response to arrive removed all other in-flight requests'
// listeners, so their responses never resolved and each hung until the 30s
// ToPeer timeout. Callers were forced to serialize every request through one
// AuthFetch. With the fix, concurrent requests on one client (one session)
// must all resolve promptly.
func TestFetchConcurrentRequestsAllResolve(t *testing.T) {
	ts := buildInProcessBRC31Server(t, 0)

	clientWallet := wallet.NewTestWalletForRandomKey(t)
	af := New(clientWallet, WithoutLogging())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Warm up: establish the session with a single serial request first so the
	// concurrent phase exercises general messages, not handshake racing.
	resp, err := af.Fetch(ctx, ts.URL+"/warmup", &SimplifiedFetchRequestOptions{Method: "GET"})
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	const (
		rounds      = 3
		concurrency = 8
	)
	for round := 0; round < rounds; round++ {
		var wg sync.WaitGroup
		errs := make([]error, concurrency)
		statuses := make([]int, concurrency)
		start := time.Now()
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				resp, err := af.Fetch(ctx, ts.URL+"/test", &SimplifiedFetchRequestOptions{Method: "GET"})
				if err != nil {
					errs[i] = err
					return
				}
				statuses[i] = resp.StatusCode
				_ = resp.Body.Close()
			}(i)
		}
		wg.Wait()

		for i := 0; i < concurrency; i++ {
			require.NoError(t, errs[i], "round %d request %d", round, i)
			require.Equal(t, http.StatusOK, statuses[i], "round %d request %d", round, i)
		}
		// Pre-fix, all-but-one request per round waited for the 30s ToPeer
		// timeout; post-fix the whole round completes in normal request time.
		require.Less(t, time.Since(start), 10*time.Second,
			"round %d: concurrent requests must not wait on the ToPeer timeout", round)
	}
}
