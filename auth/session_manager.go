package auth

import (
	"errors"
	"sync"
)

// SessionManager defines the interface for managing peer sessions.
type SessionManager interface {
	AddSession(session *PeerSession) error
	UpdateSession(session *PeerSession)
	GetSession(identifier string) (*PeerSession, error)
	RemoveSession(session *PeerSession)
	HasSession(identifier string) bool
}

// ensure that DefaultSessionManager is implementing SessionManager
var _ SessionManager = (*DefaultSessionManager)(nil)

// DefaultSessionManager manages sessions for peers, allowing multiple concurrent sessions
// per identity key. Primary lookup is always by sessionNonce.
type DefaultSessionManager struct {
	// Maps sessionNonce -> PeerSession
	sessionNonceToSession sync.Map

	keyToNoncesLock sync.RWMutex

	// Maps identityKey -> Set of sessionNonces
	identityKeyToNonces map[string]map[string]struct{}
}

// NewSessionManager creates a new session manager
func NewSessionManager() *DefaultSessionManager {
	return &DefaultSessionManager{
		identityKeyToNonces: make(map[string]map[string]struct{}),
	}
}

// AddSession adds a session to the manager, associating it with its sessionNonce,
// and also with its peerIdentityKey (if any).
//
// This does NOT overwrite existing sessions for the same peerIdentityKey,
// allowing multiple concurrent sessions for the same peer.
func (sm *DefaultSessionManager) AddSession(session *PeerSession) error {
	if session.SessionNonce == "" {
		return errors.New("invalid session: sessionNonce is required to add a session")
	}

	// Use the sessionNonce as the primary key
	sm.sessionNonceToSession.Store(session.SessionNonce, session)

	// Also track it by identity key if present
	if session.PeerIdentityKey != nil {
		sm.keyToNoncesLock.Lock()
		defer sm.keyToNoncesLock.Unlock()
		nonces := sm.identityKeyToNonces[session.PeerIdentityKey.ToDERHex()]
		if nonces == nil {
			nonces = make(map[string]struct{})
			sm.identityKeyToNonces[session.PeerIdentityKey.ToDERHex()] = nonces
		}
		nonces[session.SessionNonce] = struct{}{}
	}

	return nil
}

// UpdateSession updates a session in the manager (primarily by re-adding it),
// ensuring we record the latest data (e.g., isAuthenticated, lastUpdate, etc.).
func (sm *DefaultSessionManager) UpdateSession(session *PeerSession) {
	// Remove the old references (if any) and re-add
	sm.RemoveSession(session)
	_ = sm.AddSession(session)
}

// GetSession retrieves a session based on a given identifier, which can be:
// - A sessionNonce, or
// - A peerIdentityKey.
//
// If it is a sessionNonce, returns that exact session.
// If it is a peerIdentityKey, returns the "best" (e.g. most recently updated,
// authenticated) session associated with that peer, if any.
func (sm *DefaultSessionManager) GetSession(identifier string) (*PeerSession, error) {
	// Check if this identifier is directly a sessionNonce
	if direct, ok := sm.sessionNonceToSession.Load(identifier); ok {
		return direct.(*PeerSession), nil
	}

	// Otherwise, interpret the identifier as an identity key
	sm.keyToNoncesLock.RLock()
	defer sm.keyToNoncesLock.RUnlock()
	nonces, ok := sm.identityKeyToNonces[identifier]
	if !ok || len(nonces) == 0 {
		return nil, errors.New("session-not-found")
	}

	// Pick the "best" session
	// - Choose the most recently updated, preferring authenticated sessions
	var best *PeerSession
	for nonce := range nonces {
		if s, ok := sm.sessionNonceToSession.Load(nonce); ok {
			s := s.(*PeerSession)
			if best == nil {
				best = s
			} else if s.LastUpdate > best.LastUpdate {
				if s.IsAuthenticated || !best.IsAuthenticated {
					best = s
				}
			} else if s.IsAuthenticated && !best.IsAuthenticated {
				best = s
			}
		}
	}

	return best, nil
}

// RemoveSession removes a session from the manager by clearing all associated identifiers.
func (sm *DefaultSessionManager) RemoveSession(session *PeerSession) {
	if session.SessionNonce != "" {
		sm.sessionNonceToSession.Delete(session.SessionNonce)
	}

	if session.PeerIdentityKey != nil {
		sm.keyToNoncesLock.Lock()
		defer sm.keyToNoncesLock.Unlock()
		nonces := sm.identityKeyToNonces[session.PeerIdentityKey.ToDERHex()]
		if nonces != nil {
			delete(nonces, session.SessionNonce)
			if len(nonces) == 0 {
				delete(sm.identityKeyToNonces, session.PeerIdentityKey.ToDERHex())
			}
		}
	}
}

// HasSession checks if a session exists for a given identifier (either sessionNonce or identityKey).
func (sm *DefaultSessionManager) HasSession(identifier string) bool {
	// Check if the identifier is a sessionNonce
	_, ok := sm.sessionNonceToSession.Load(identifier)
	if ok {
		return true
	}

	// If not directly a nonce, interpret as identityKey
	sm.keyToNoncesLock.RLock()
	defer sm.keyToNoncesLock.RUnlock()
	nonces, ok := sm.identityKeyToNonces[identifier]
	return ok && len(nonces) > 0
}
