package auth

import "errors"

type sessionManager struct {
	sessionNonceToSession map[string]*PeerSession
	identityKeyToNonce    map[string]map[string]struct{}
}

func NewSessionManager() *sessionManager {
	return &sessionManager{
		sessionNonceToSession: make(map[string]*PeerSession),
		identityKeyToNonce:    make(map[string]map[string]struct{}),
	}
}

func (sm *sessionManager) AddSession(session *PeerSession) error {
	if session.SessionNonce == "" {
		return errors.New("invalid-session-nonce")
	}
	sm.sessionNonceToSession[session.SessionNonce] = session
	if session.PeerIdentityKey != "" {
		nonces := sm.identityKeyToNonce[session.PeerIdentityKey]
		if nonces == nil {
			nonces = make(map[string]struct{})
			sm.identityKeyToNonce[session.PeerIdentityKey] = nonces
		}
		nonces[session.SessionNonce] = struct{}{}
	}
	return nil
}

func (sm *sessionManager) UpdateSession(session *PeerSession) {
	sm.RemoveSession(session)
	_ = sm.AddSession(session)
}

func (sm *sessionManager) GetSession(identifier string) *PeerSession {
	if direct, ok := sm.sessionNonceToSession[identifier]; ok {
		return direct
	} else if nonces, ok := sm.identityKeyToNonce[identifier]; !ok || len(nonces) == 0 {
		return nil
	} else {
		var best *PeerSession
		for nonce := range nonces {
			if s, ok := sm.sessionNonceToSession[nonce]; ok {
				if best == nil {
					best = s
				} else if s.LastUpdated > best.LastUpdated {
					best = s
				}
			}
		}
		return best
	}
}

func (sm *sessionManager) RemoveSession(session *PeerSession) {
	if session.SessionNonce != "" {
		delete(sm.sessionNonceToSession, session.SessionNonce)
	}
	if session.PeerIdentityKey != "" {
		nonces := sm.identityKeyToNonce[session.PeerIdentityKey]
		if nonces != nil {
			delete(nonces, session.SessionNonce)
			if len(nonces) == 0 {
				delete(sm.identityKeyToNonce, session.PeerIdentityKey)
			}
		}
	}
}

func (sm *sessionManager) HasSession(identifier string) bool {
	if _, ok := sm.sessionNonceToSession[identifier]; ok {
		return true
	} else if nonces, ok := sm.identityKeyToNonce[identifier]; ok && len(nonces) > 0 {
		for nonce := range nonces {
			if _, ok := sm.sessionNonceToSession[nonce]; ok {
				return true
			}
		}
	}
	return false
}
