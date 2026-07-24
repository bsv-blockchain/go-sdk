package auth_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// TestSessionManager_UpdateSessionHasNoRemovalWindow is a regression test for
// UpdateSession being implemented as RemoveSession+AddSession: peers call
// UpdateSession after every handled message, and the removal window made
// concurrent GetSession lookups by sessionNonce randomly fail with
// session-not-found, so servers rejected valid concurrent requests on one
// session.
func TestSessionManager_UpdateSessionHasNoRemovalWindow(t *testing.T) {
	manager := auth.NewSessionManager()

	pk, err := ec.NewPrivateKey()
	require.NoError(t, err)
	session := &auth.PeerSession{
		IsAuthenticated: true,
		SessionNonce:    "shared-nonce",
		PeerNonce:       "peer-nonce",
		PeerIdentityKey: pk.PubKey(),
		LastUpdate:      time.Now().UnixNano() / int64(time.Millisecond),
	}
	require.NoError(t, manager.AddSession(session))

	const iterations = 5_000
	var wg sync.WaitGroup
	wg.Add(2)

	// Writer: hammer UpdateSession like a peer handling a message stream.
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			manager.UpdateSession(session)
		}
	}()

	// Reader: every lookup by nonce must succeed for the whole run.
	var lookupErr error
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if _, err := manager.GetSession("shared-nonce"); err != nil {
				lookupErr = err
				return
			}
		}
	}()

	wg.Wait()
	require.NoError(t, lookupErr, "GetSession by nonce must never fail while UpdateSession runs")
}
