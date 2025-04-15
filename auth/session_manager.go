package auth

import "errors"

// SessionManager manages sessions for peers, allowing multiple concurrent sessions
// per identity key. Primary lookup is always by sessionNonce.
type SessionManager struct {
	// Maps sessionNonce -> PeerSession
	sessionNonceToSession map[string]*PeerSession

	// Maps identityKey -> Set of sessionNonces
	identityKeyToNonces map[string]map[string]struct{}
}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessionNonceToSession: make(map[string]*PeerSession),
		identityKeyToNonces:   make(map[string]map[string]struct{}),
	}
}

// AddSession adds a session to the manager, associating it with its sessionNonce,
// and also with its peerIdentityKey (if any).
//
// This does NOT overwrite existing sessions for the same peerIdentityKey,
// allowing multiple concurrent sessions for the same peer.
func (sm *SessionManager) AddSession(session *PeerSession) error {
	if session.SessionNonce == "" {
		return errors.New("invalid session: sessionNonce is required to add a session")
	}

	// Use the sessionNonce as the primary key
	sm.sessionNonceToSession[session.SessionNonce] = session

	// Also track it by identity key if present
	if session.PeerIdentityKey != nil {
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
func (sm *SessionManager) UpdateSession(session *PeerSession) {
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
func (sm *SessionManager) GetSession(identifier string) (*PeerSession, error) {
	// Check if this identifier is directly a sessionNonce
	if direct, ok := sm.sessionNonceToSession[identifier]; ok {
		return direct, nil
	}

	// Otherwise, interpret the identifier as an identity key
	nonces, ok := sm.identityKeyToNonces[identifier]
	if !ok || len(nonces) == 0 {
		return nil, errors.New("session-not-found")
	}

	// Pick the "best" session
	// - Choose the most recently updated, preferring authenticated sessions
	var best *PeerSession
	for nonce := range nonces {
		if s, ok := sm.sessionNonceToSession[nonce]; ok {
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
func (sm *SessionManager) RemoveSession(session *PeerSession) {
	if session.SessionNonce != "" {
		delete(sm.sessionNonceToSession, session.SessionNonce)
	}

	if session.PeerIdentityKey != nil {
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
func (sm *SessionManager) HasSession(identifier string) bool {
	// Check if the identifier is a sessionNonce
	direct := sm.sessionNonceToSession[identifier] != nil
	if direct {
		return true
	}

	// If not directly a nonce, interpret as identityKey
	nonces, ok := sm.identityKeyToNonces[identifier]
	return ok && len(nonces) > 0
}
