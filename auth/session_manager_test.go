package auth

import (
	"testing"
	"time"
)

func TestNewSessionManager(t *testing.T) {
	manager := NewSessionManager()
	if manager == nil {
		t.Fatal("Expected session manager to be created")
	}

	if manager.sessionNonceToSession == nil {
		t.Error("Expected sessionNonceToSession map to be initialized")
	}

	if manager.identityKeyToNonces == nil {
		t.Error("Expected identityKeyToNonces map to be initialized")
	}
}

func TestSessionManager(t *testing.T) {
	manager := NewSessionManager()

	// Create a session
	session := &PeerSession{
		IsAuthenticated: true,
		SessionNonce:    "test-nonce",
		PeerNonce:       "peer-nonce",
		PeerIdentityKey: "test-key",
		LastUpdate:      time.Now().UnixNano() / int64(time.Millisecond),
	}

	// Add session
	err := manager.AddSession(session)
	if err != nil {
		t.Errorf("Failed to add session: %v", err)
	}

	// Get session by identity key
	retrievedSession, err := manager.GetSession("test-key")
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

	if retrievedSession.PeerIdentityKey != "test-key" {
		t.Errorf("Expected peer identity key 'test-key', got '%s'", retrievedSession.PeerIdentityKey)
	}

	// Test HasSession
	if !manager.HasSession("test-key") {
		t.Error("Expected HasSession to return true for identity key")
	}

	if !manager.HasSession("test-nonce") {
		t.Error("Expected HasSession to return true for session nonce")
	}

	// Update session
	retrievedSession.IsAuthenticated = false
	manager.UpdateSession(retrievedSession)

	// Verify update
	retrievedSession, err = manager.GetSession("test-key")
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
	invalidSession := &PeerSession{
		IsAuthenticated: true,
		PeerIdentityKey: "test-key-2",
		LastUpdate:      time.Now().UnixNano() / int64(time.Millisecond),
	}

	err = manager.AddSession(invalidSession)
	if err == nil {
		t.Error("Expected error when adding session with no nonce")
	}
}
