package auth_test

import (
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/require"
)

func TestSessionManager(t *testing.T) {
	manager := auth.NewSessionManager()

	pk, err := ec.NewPrivateKey()
	require.NoError(t, err)
	// Create a session
	session := &auth.PeerSession{
		IsAuthenticated: true,
		SessionNonce:    "test-nonce",
		PeerNonce:       "peer-nonce",
		PeerIdentityKey: pk.PubKey(),
		LastUpdate:      time.Now().UnixNano() / int64(time.Millisecond),
	}

	// Add session
	err = manager.AddSession(session)
	if err != nil {
		t.Errorf("Failed to add session: %v", err)
	}

	// Get session by identity key
	retrievedSession, err := manager.GetSession("test-nonce")
	if err != nil {
		t.Errorf("Failed to retrieve session by identity key: %v", err)
	}

	if retrievedSession.SessionNonce != "test-nonce" {
		t.Errorf("Expected session nonce 'test-nonce', got '%s'", retrievedSession.SessionNonce)
	}

	// Get session by session nonce
	retrievedSession, err = manager.GetSession("test-nonce")
	if err != nil {
		t.Errorf("Failed to retrieve session by nonce: %v", err)
	}

	if retrievedSession.PeerIdentityKey != pk.PubKey() {
		t.Errorf("Expected peer identity key '%s', got '%s'", pk.PubKey(), retrievedSession.PeerIdentityKey)
	}

	// Test HasSession
	if !manager.HasSession("test-nonce") {
		t.Error("Expected HasSession to return true for identity key")
	}

	if !manager.HasSession("test-nonce") {
		t.Error("Expected HasSession to return true for session nonce")
	}

	// Update session
	retrievedSession.IsAuthenticated = false
	manager.UpdateSession(retrievedSession)

	// Verify update
	retrievedSession, err = manager.GetSession("test-nonce")
	if err != nil {
		t.Errorf("Failed to retrieve updated session: %v", err)
	}

	if retrievedSession.IsAuthenticated {
		t.Error("Expected IsAuthenticated to be false after update")
	}

	// Remove session
	manager.RemoveSession(retrievedSession)

	// Verify removed
	_, err = manager.GetSession("test-key")
	if err == nil {
		t.Error("Expected error when retrieving removed session")
	}

	// Test adding session with missing nonce
	invalidSession := &auth.PeerSession{
		IsAuthenticated: true,
		PeerIdentityKey: pk.PubKey(),
		LastUpdate:      time.Now().UnixNano() / int64(time.Millisecond),
	}

	err = manager.AddSession(invalidSession)
	if err == nil {
		t.Error("Expected error when adding session with no nonce")
	}
}
