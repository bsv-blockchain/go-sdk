package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// bobsSessionWithAlice authenticates Alice to Bob and returns Bob's session
// for her.
func bobsSessionWithAlice(t *testing.T) (alice, bob *Actor, session *auth.PeerSession) {
	t.Helper()
	alice, bob = CreateActorsPair(t)
	received := make(chan struct{}, 1)
	id := bob.ListenForGeneralMessages(func(context.Context, *ec.PublicKey, []byte) error {
		received <- struct{}{}
		return nil
	})
	require.NoError(t, alice.ToPeer(t.Context(), anyMessage, bob.IdentityKey, 5000))
	select {
	case <-received:
	case <-time.After(500 * time.Millisecond):
		require.Fail(t, "Bob never received Alice's first message")
	}
	bob.StopListeningForGeneralMessages(id)
	session, err := bob.SessionManager.GetSession(alice.IdentityKey.ToDERHex())
	require.NoError(t, err)
	require.True(t, session.IsAuthenticated)
	return alice, bob, session
}

func TestToPeerOnSessionSendsOnTheNamedSession(t *testing.T) {
	alice, bob, session := bobsSessionWithAlice(t)

	got := make(chan []byte, 1)
	alice.ListenForGeneralMessages(func(_ context.Context, _ *ec.PublicKey, payload []byte) error {
		got <- payload
		return nil
	})
	reply := []byte("reply on your session")
	require.NoError(t, bob.ToPeerOnSession(t.Context(), reply, session.SessionNonce))

	select {
	case payload := <-got:
		require.Equal(t, reply, payload)
	case <-time.After(500 * time.Millisecond):
		require.Fail(t, "Alice never received the reply")
	}
}

func TestToPeerOnSessionRefusesAnythingButAnExactAuthenticatedSession(t *testing.T) {
	alice, bob, session := bobsSessionWithAlice(t)

	// An unknown nonce is not a session.
	err := bob.ToPeerOnSession(t.Context(), anyMessage, "no-such-nonce")
	require.ErrorIs(t, err, auth.ErrSessionNotFound)

	// GetSession would read an identity key as "that identity's best session";
	// ToPeerOnSession must not, or it would reintroduce the problem it solves.
	err = bob.ToPeerOnSession(t.Context(), anyMessage, alice.IdentityKey.ToDERHex())
	require.ErrorIs(t, err, auth.ErrSessionNotFound)

	// A session that is not authenticated is never written to.
	session.IsAuthenticated = false
	bob.SessionManager.UpdateSession(session)
	err = bob.ToPeerOnSession(t.Context(), anyMessage, session.SessionNonce)
	require.ErrorIs(t, err, auth.ErrNotAuthenticated)
}
