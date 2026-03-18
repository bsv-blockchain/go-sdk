package auth_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/bsv-blockchain/go-sdk/auth"
	certpkg "github.com/bsv-blockchain/go-sdk/auth/certificates"
	utilspkg "github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

const soloNonce = "solo-nonce"

// newTestPeer creates a Peer with two connected mock transports for testing
func newTestPeer(t *testing.T, privKeyHex string) (*auth.Peer, *MockTransport, *MockTransport) {
	t.Helper()
	pk, err := ec.PrivateKeyFromHex(privKeyHex)
	require.NoError(t, err)
	w, err := wallet.NewCompletedProtoWallet(pk)
	require.NoError(t, err)

	tr := NewMockTransport("peer-" + privKeyHex[:8])
	peer := auth.NewPeer(&auth.PeerOptions{
		Wallet:    w,
		Transport: tr,
	})
	return peer, tr, nil
}

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
		require.Greater(t, id, int32(0))
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
		require.Greater(t, id, int32(0))
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
		require.Greater(t, id, int32(0))
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
