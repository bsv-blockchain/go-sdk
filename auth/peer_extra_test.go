package auth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/auth"
	certpkg "github.com/bsv-blockchain/go-sdk/auth/certificates"
	utilspkg "github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const soloNonce = "solo-nonce"

func TestPeerStop(t *testing.T) {
	t.Run("stop returns nil", func(t *testing.T) {
		pk, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
		require.NoError(t, err)
		w, err := wallet.NewCompletedProtoWallet(pk)
		require.NoError(t, err)
		tr := NewMockTransport("test")
		peer := auth.NewPeer(&auth.PeerOptions{
			Wallet:    w,
			Transport: tr,
		})
		err = peer.Stop()
		require.NoError(t, err)
	})
}

func TestPeerSetLogger(t *testing.T) {
	t.Run("set logger does not panic", func(t *testing.T) {
		pk, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
		require.NoError(t, err)
		w, err := wallet.NewCompletedProtoWallet(pk)
		require.NoError(t, err)
		tr := NewMockTransport("test")
		peer := auth.NewPeer(&auth.PeerOptions{
			Wallet:    w,
			Transport: tr,
		})
		logger := slog.Default()
		peer.SetLogger(logger)
	})
}

func TestPeerListenCallbacks(t *testing.T) {
	pk, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
	require.NoError(t, err)
	w, err := wallet.NewCompletedProtoWallet(pk)
	require.NoError(t, err)
	tr := NewMockTransport("test")
	peer := auth.NewPeer(&auth.PeerOptions{
		Wallet:    w,
		Transport: tr,
	})

	t.Run("ListenForGeneralMessages returns callback ID", func(t *testing.T) {
		id := peer.ListenForGeneralMessages(func(ctx context.Context, senderPublicKey *ec.PublicKey, payload []byte) error {
			return nil
		})
		require.Positive(t, id)
	})

	t.Run("StopListeningForGeneralMessages does not panic", func(t *testing.T) {
		id := peer.ListenForGeneralMessages(func(ctx context.Context, senderPublicKey *ec.PublicKey, payload []byte) error {
			return nil
		})
		peer.StopListeningForGeneralMessages(id)
	})

	t.Run("ListenForCertificatesReceived returns callback ID", func(t *testing.T) {
		id := peer.ListenForCertificatesReceived(func(ctx context.Context, senderPublicKey *ec.PublicKey, certs []*certpkg.VerifiableCertificate) error {
			return nil
		})
		require.Positive(t, id)
	})

	t.Run("StopListeningForCertificatesReceived does not panic", func(t *testing.T) {
		id := peer.ListenForCertificatesReceived(func(ctx context.Context, senderPublicKey *ec.PublicKey, certs []*certpkg.VerifiableCertificate) error {
			return nil
		})
		peer.StopListeningForCertificatesReceived(id)
	})

	t.Run("ListenForCertificatesRequested returns callback ID", func(t *testing.T) {
		id := peer.ListenForCertificatesRequested(func(ctx context.Context, senderPublicKey *ec.PublicKey, req utilspkg.RequestedCertificateSet) error {
			return nil
		})
		require.Positive(t, id)
	})

	t.Run("StopListeningForCertificatesRequested does not panic", func(t *testing.T) {
		id := peer.ListenForCertificatesRequested(func(ctx context.Context, senderPublicKey *ec.PublicKey, req utilspkg.RequestedCertificateSet) error {
			return nil
		})
		peer.StopListeningForCertificatesRequested(id)
	})

	t.Run("StopListeningForInitialResponse does not panic", func(t *testing.T) {
		// Use a non-existent callback ID
		peer.StopListeningForInitialResponse(9999)
	})
}

func TestAuthMessageMarshalJSON(t *testing.T) {
	t.Run("marshal with valid identity key", func(t *testing.T) {
		pk, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
		require.NoError(t, err)

		msg := &auth.AuthMessage{
			Version:     "0.1",
			MessageType: auth.MessageTypeGeneral,
			IdentityKey: pk.PubKey(),
			Nonce:       "test-nonce",
			Payload:     []byte("hello"),
		}

		data, err := json.Marshal(msg)
		require.NoError(t, err)
		require.NotEmpty(t, data)

		// Verify the identity key is encoded as hex
		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)
		require.Contains(t, result, "identityKey")
	})

	t.Run("marshal fails with nil identity key", func(t *testing.T) {
		msg := &auth.AuthMessage{
			Version:     "0.1",
			MessageType: auth.MessageTypeGeneral,
			IdentityKey: nil,
		}

		_, err := json.Marshal(msg)
		require.Error(t, err)
	})

	t.Run("general message always carries payload, even when empty", func(t *testing.T) {
		// BRC-103 requires general.payload to be present (an empty message is
		// valid); a plain []byte field with `omitempty` would otherwise drop
		// it whenever the payload has zero bytes.
		pk, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
		require.NoError(t, err)
		msg := &auth.AuthMessage{
			Version:     "0.1",
			MessageType: auth.MessageTypeGeneral,
			IdentityKey: pk.PubKey(),
			Nonce:       "test-nonce",
			// Payload intentionally left nil/empty.
		}

		data, err := json.Marshal(msg)
		require.NoError(t, err)

		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &result))
		require.Contains(t, result, "payload")
		payload, ok := result["payload"].([]interface{})
		require.True(t, ok, "payload must decode as an array, not null")
		require.Empty(t, payload)
	})

	t.Run("certificateResponse always carries certificates, even when empty", func(t *testing.T) {
		// The TS reference validator rejects a certificateResponse whose
		// certificates field is missing or null.
		pk, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
		require.NoError(t, err)
		msg := &auth.AuthMessage{
			Version:     "0.1",
			MessageType: auth.MessageTypeCertificateResponse,
			IdentityKey: pk.PubKey(),
			Nonce:       "test-nonce",
			// Certificates intentionally left nil.
		}

		data, err := json.Marshal(msg)
		require.NoError(t, err)

		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &result))
		require.Contains(t, result, "certificates")
		certs, ok := result["certificates"].([]interface{})
		require.True(t, ok, "certificates must decode as an array, not null")
		require.Empty(t, certs)
	})

	t.Run("non-general, non-certificateResponse messages omit unset payload and certificates", func(t *testing.T) {
		pk, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
		require.NoError(t, err)
		msg := &auth.AuthMessage{
			Version:      "0.1",
			MessageType:  auth.MessageTypeInitialResponse,
			IdentityKey:  pk.PubKey(),
			InitialNonce: "abc",
			YourNonce:    "def",
			Signature:    []byte{1, 2, 3},
		}

		data, err := json.Marshal(msg)
		require.NoError(t, err)

		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &result))
		require.NotContains(t, result, "payload")
		require.NotContains(t, result, "certificates")
	})
}

func TestAuthMessageUnmarshalJSON(t *testing.T) {
	t.Run("unmarshal roundtrip", func(t *testing.T) {
		pk, err := ec.PrivateKeyFromHex(alicePrivKeyHex)
		require.NoError(t, err)

		original := &auth.AuthMessage{
			Version:     "0.1",
			MessageType: auth.MessageTypeInitialRequest,
			IdentityKey: pk.PubKey(),
			Nonce:       "abc123",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var restored auth.AuthMessage
		err = json.Unmarshal(data, &restored)
		require.NoError(t, err)
		require.Equal(t, original.Version, restored.Version)
		require.Equal(t, original.MessageType, restored.MessageType)
		require.Equal(t, original.Nonce, restored.Nonce)
		require.True(t, restored.IdentityKey.IsEqual(pk.PubKey()))
	})

	t.Run("unmarshal fails with invalid identity key", func(t *testing.T) {
		data := []byte(`{"version":"0.1","messageType":"general","identityKey":"invalidkey","nonce":"x"}`)
		var msg auth.AuthMessage
		err := json.Unmarshal(data, &msg)
		require.Error(t, err)
	})
}

func TestSessionManagerExtra(t *testing.T) {
	t.Run("GetSession by identity key returns authenticated session preferentially", func(t *testing.T) {
		sm := auth.NewSessionManager()

		pk, err := ec.NewPrivateKey()
		require.NoError(t, err)

		// Add an unauthenticated session
		s1 := &auth.PeerSession{
			SessionNonce:    "nonce-1",
			PeerIdentityKey: pk.PubKey(),
			IsAuthenticated: false,
			LastUpdate:      1000,
		}
		err = sm.AddSession(s1)
		require.NoError(t, err)

		// Add an authenticated session
		s2 := &auth.PeerSession{
			SessionNonce:    "nonce-2",
			PeerIdentityKey: pk.PubKey(),
			IsAuthenticated: true,
			LastUpdate:      500, // older but authenticated
		}
		err = sm.AddSession(s2)
		require.NoError(t, err)

		// Should return the authenticated one
		best, err := sm.GetSession(pk.PubKey().ToDERHex())
		require.NoError(t, err)
		require.True(t, best.IsAuthenticated)
	})

	t.Run("HasSession by identity key returns false after remove", func(t *testing.T) {
		sm := auth.NewSessionManager()

		pk, err := ec.NewPrivateKey()
		require.NoError(t, err)

		s := &auth.PeerSession{
			SessionNonce:    "test-nonce-xyz",
			PeerIdentityKey: pk.PubKey(),
			IsAuthenticated: true,
			LastUpdate:      1000,
		}
		err = sm.AddSession(s)
		require.NoError(t, err)

		require.True(t, sm.HasSession(pk.PubKey().ToDERHex()))

		sm.RemoveSession(s)
		require.False(t, sm.HasSession(pk.PubKey().ToDERHex()))
	})

	t.Run("HasSession returns false for unknown identifier", func(t *testing.T) {
		sm := auth.NewSessionManager()
		require.False(t, sm.HasSession("completely-unknown-identifier"))
	})

	t.Run("GetSession returns error when identity key has no sessions", func(t *testing.T) {
		sm := auth.NewSessionManager()
		pk, err := ec.NewPrivateKey()
		require.NoError(t, err)
		_, err = sm.GetSession(pk.PubKey().ToDERHex())
		require.Error(t, err)
	})

	t.Run("RemoveSession on session without identity key", func(t *testing.T) {
		sm := auth.NewSessionManager()
		s := &auth.PeerSession{
			SessionNonce:    soloNonce,
			PeerIdentityKey: nil,
			IsAuthenticated: false,
		}
		err := sm.AddSession(s)
		require.NoError(t, err)
		require.True(t, sm.HasSession(soloNonce))

		sm.RemoveSession(s)
		require.False(t, sm.HasSession(soloNonce))
	})
}

// replayTransport is a minimal, directly-paired auth.Transport (like
// MockTransport above, but exposing its registered handler and an onSend
// hook) used by the replay-protection tests below to capture a real,
// validly-signed AuthMessage as it leaves one Peer and redeliver it to the
// other Peer's handler directly, simulating a network-level replay.
type replayTransport struct {
	name    string
	peer    *replayTransport
	handler func(context.Context, *auth.AuthMessage) error
	onSend  func(*auth.AuthMessage)
}

func (t *replayTransport) Send(ctx context.Context, message *auth.AuthMessage) error {
	if t.onSend != nil {
		t.onSend(message)
	}
	if t.peer == nil || t.peer.handler == nil {
		return fmt.Errorf("%s: paired transport has no handler registered", t.name)
	}
	return t.peer.handler(ctx, message)
}

func (t *replayTransport) OnData(callback func(context.Context, *auth.AuthMessage) error) error {
	t.handler = callback
	return nil
}

func (t *replayTransport) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	if t.handler == nil {
		return nil, fmt.Errorf("%s: no handler registered", t.name)
	}
	return t.handler, nil
}

// TestPeerRejectsReplayedGeneralMessageNonce is an end-to-end regression test
// for BRC-103 anti-replay: a real, validly-signed general message that Bob
// already accepted once must be rejected as auth.ErrReplayedNonce when
// redelivered with the exact same nonce, mirroring the TS reference Peer's
// claimMessageNonce enforcement.
func TestPeerRejectsReplayedGeneralMessageNonce(t *testing.T) {
	alicePriv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	bobPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	aliceWallet := wallet.NewTestWallet(t, alicePriv)
	bobWallet := wallet.NewTestWallet(t, bobPriv)

	aliceTransport := &replayTransport{name: "alice"}
	bobTransport := &replayTransport{name: "bob"}
	aliceTransport.peer = bobTransport
	bobTransport.peer = aliceTransport

	var captured *auth.AuthMessage
	aliceTransport.onSend = func(msg *auth.AuthMessage) {
		if msg.MessageType == auth.MessageTypeGeneral {
			captured = msg
		}
	}

	alice := auth.NewPeer(&auth.PeerOptions{Wallet: aliceWallet, Transport: aliceTransport})
	bob := auth.NewPeer(&auth.PeerOptions{Wallet: bobWallet, Transport: bobTransport})

	received := make(chan struct{}, 2)
	bob.ListenForGeneralMessages(func(context.Context, *ec.PublicKey, []byte) error {
		received <- struct{}{}
		return nil
	})

	require.NoError(t, alice.ToPeer(t.Context(), []byte("hello"), bobPriv.PubKey(), 5000))
	select {
	case <-received:
	default:
		t.Fatal("bob never received alice's general message")
	}
	require.NotNil(t, captured, "expected to capture alice's outgoing general message")

	// Redeliver the exact same message directly to Bob's handler, simulating
	// a network-level replay of an already-consumed nonce.
	handler, err := bobTransport.GetRegisteredOnData()
	require.NoError(t, err)
	err = handler(t.Context(), captured)
	require.Error(t, err)
	require.ErrorIs(t, err, auth.ErrReplayedNonce)

	// The replay must not have reached the application-level listener again.
	select {
	case <-received:
		t.Fatal("replayed general message was delivered to the listener a second time")
	default:
	}
}

// TestPeerRejectsReplayedInitialRequestNonce covers the unsigned handshake
// side of anti-replay (mirroring the TS reference's
// claimInitialRequestNonce / auth.brc31-handshake.14): redelivering the same
// initialRequest (same identityKey + initialNonce) must be rejected even
// though it carries no signature to re-verify.
func TestPeerRejectsReplayedInitialRequestNonce(t *testing.T) {
	alicePriv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	bobPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	bobWallet := wallet.NewTestWallet(t, bobPriv)

	// bobTransport's paired "peer" is a bare sink that accepts Bob's
	// initialResponse without doing anything further with it - this test
	// only cares about how Bob's incoming-message handler treats a replayed
	// initialRequest, not about a real round trip.
	sink := &replayTransport{name: "sink"}
	require.NoError(t, sink.OnData(func(context.Context, *auth.AuthMessage) error { return nil }))
	bobTransport := &replayTransport{name: "bob", peer: sink}
	_ = auth.NewPeer(&auth.PeerOptions{Wallet: bobWallet, Transport: bobTransport})

	initialRequest := &auth.AuthMessage{
		Version:      auth.AUTH_VERSION,
		MessageType:  auth.MessageTypeInitialRequest,
		IdentityKey:  alicePriv.PubKey(),
		InitialNonce: string(utilspkg.RandomBase64(32)),
	}

	handler, err := bobTransport.GetRegisteredOnData()
	require.NoError(t, err)

	require.NoError(t, handler(t.Context(), initialRequest))

	err = handler(t.Context(), initialRequest)
	require.Error(t, err)
	require.ErrorIs(t, err, auth.ErrReplayedNonce)
}

// TestPeerRejectsConcurrentReplayedGeneralMessageNonce drives many concurrent
// deliveries of the exact same, already-captured general message at Bob and
// asserts exactly one succeeds - the nonce claim must be atomic under
// concurrency. Run with -race.
func TestPeerRejectsConcurrentReplayedGeneralMessageNonce(t *testing.T) {
	const concurrency = 25

	alicePriv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	bobPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	aliceWallet := wallet.NewTestWallet(t, alicePriv)
	bobWallet := wallet.NewTestWallet(t, bobPriv)

	aliceTransport := &replayTransport{name: "alice"}
	bobTransport := &replayTransport{name: "bob"}
	aliceTransport.peer = bobTransport
	bobTransport.peer = aliceTransport

	var (
		resultsMu sync.Mutex
		results   []error
	)

	// Fire (concurrency-1) extra concurrent deliveries of the captured
	// message the instant it is sent, racing with the "official" delivery
	// that follows immediately after this hook returns.
	aliceTransport.onSend = func(msg *auth.AuthMessage) {
		if msg.MessageType != auth.MessageTypeGeneral {
			return
		}
		var wg sync.WaitGroup
		for i := 0; i < concurrency-1; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := bobTransport.handler(context.Background(), msg)
				resultsMu.Lock()
				results = append(results, err)
				resultsMu.Unlock()
			}()
		}
		wg.Wait()
	}

	alice := auth.NewPeer(&auth.PeerOptions{Wallet: aliceWallet, Transport: aliceTransport})
	bob := auth.NewPeer(&auth.PeerOptions{Wallet: bobWallet, Transport: bobTransport})

	received := make(chan struct{}, concurrency)
	bob.ListenForGeneralMessages(func(context.Context, *ec.PublicKey, []byte) error {
		received <- struct{}{}
		return nil
	})

	sendErr := alice.ToPeer(t.Context(), []byte("hello"), bobPriv.PubKey(), 5000)
	resultsMu.Lock()
	results = append(results, sendErr)
	resultsMu.Unlock()

	require.Len(t, results, concurrency)
	successes := 0
	for _, resultErr := range results {
		if resultErr == nil {
			successes++
			continue
		}
		require.ErrorIs(t, resultErr, auth.ErrReplayedNonce)
	}
	require.Equal(t, 1, successes, "exactly one of %d concurrent deliveries of the same nonce must succeed", concurrency)
	require.Len(t, received, successes, "the listener must be notified exactly once")
}

// legacySessionManager only exposes the base auth.SessionManager methods, like
// a custom implementation written before auth.NonceClaimer existed.
type legacySessionManager struct {
	auth.SessionManager
}

// TestPeerReplayProtectionWithLegacySessionManager proves a SessionManager that
// does not implement auth.NonceClaimer keeps authenticating and still gets
// replay protection from the Peer-owned fallback cache.
func TestPeerReplayProtectionWithLegacySessionManager(t *testing.T) {
	alicePriv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	bobPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	aliceTransport := &replayTransport{name: "alice"}
	bobTransport := &replayTransport{name: "bob"}
	aliceTransport.peer = bobTransport
	bobTransport.peer = aliceTransport

	var captured *auth.AuthMessage
	aliceTransport.onSend = func(msg *auth.AuthMessage) {
		if msg.MessageType == auth.MessageTypeGeneral {
			captured = msg
		}
	}

	bobSessions := legacySessionManager{SessionManager: auth.NewSessionManager()}
	var _ auth.SessionManager = bobSessions
	_, implementsClaimer := any(bobSessions).(auth.NonceClaimer)
	require.False(t, implementsClaimer)

	alice := auth.NewPeer(&auth.PeerOptions{Wallet: wallet.NewTestWallet(t, alicePriv), Transport: aliceTransport})
	bob := auth.NewPeer(&auth.PeerOptions{
		Wallet:         wallet.NewTestWallet(t, bobPriv),
		Transport:      bobTransport,
		SessionManager: bobSessions,
	})

	received := make(chan struct{}, 2)
	bob.ListenForGeneralMessages(func(context.Context, *ec.PublicKey, []byte) error {
		received <- struct{}{}
		return nil
	})

	require.NoError(t, alice.ToPeer(t.Context(), []byte("hello"), bobPriv.PubKey(), 5000))
	select {
	case <-received:
	default:
		t.Fatal("bob never received alice's general message")
	}
	require.NotNil(t, captured)

	handler, err := bobTransport.GetRegisteredOnData()
	require.NoError(t, err)
	require.ErrorIs(t, handler(t.Context(), captured), auth.ErrReplayedNonce)
}
