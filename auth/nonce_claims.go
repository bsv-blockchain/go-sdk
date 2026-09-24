package auth

import (
	"container/list"
	"sync"
)

// Default bounds for the in-process replay caches, mirroring the TS
// reference's SessionManager (DEFAULT_MAX_MESSAGE_NONCES_PER_SESSION /
// DEFAULT_MAX_INITIAL_REQUEST_NONCES in packages/sdk/src/auth/SessionManager.ts).
const (
	defaultMaxMessageNoncesPerSession = 100_000
	defaultMaxInitialRequestNonces    = 100_000

	// defaultMaxFallbackNonceSessions bounds how many sessions a Peer-owned
	// fallback cache tracks. The fallback never learns when a custom
	// SessionManager removes a session, so it evicts the oldest session's
	// cache instead.
	defaultMaxFallbackNonceSessions = 10_000
)

// NonceClaimer is implemented by a SessionManager that supports BRC-103
// replay protection: an atomic "claim this nonce once" operation for both
// signed follow-up messages (initialResponse/certificateRequest/
// certificateResponse/general) and the unsigned initialRequest handshake
// nonce, mirroring the TS reference's Peer#claimIncomingMessageNonce /
// claimInitialRequestNonce (backed by SessionManager.ts's
// claimMessageNonce/claimInitialRequestNonce).
//
// Peer uses its SessionManager for these claims when it implements
// NonceClaimer, so replay state can be shared by every Peer using that
// manager. A custom SessionManager that does not implement it keeps working:
// Peer then falls back to its own bounded in-memory cache.
type NonceClaimer interface {
	// ClaimMessageNonce atomically marks messageNonce as consumed for the
	// session identified by sessionNonce. It returns false if that nonce was
	// already claimed for that session (a replay).
	ClaimMessageNonce(sessionNonce, messageNonce string) bool

	// ClaimInitialRequestNonce atomically marks initialNonce as consumed for
	// the (unsigned, not-yet-authenticated) claimed identityKey. It returns
	// false if that (identityKey, initialNonce) pair was already claimed (a
	// replay).
	ClaimInitialRequestNonce(identityKey, initialNonce string) bool
}

// ensure that DefaultSessionManager implements NonceClaimer
var _ NonceClaimer = (*DefaultSessionManager)(nil)

// nonceClaims tracks the bounded, concurrency-safe replay caches backing
// DefaultSessionManager's NonceClaimer implementation. It is zero-value
// unusable; construct with newNonceClaims.
type nonceClaims struct {
	// messageNonces maps sessionNonce -> *nonceSet of that session's already
	// consumed message nonces.
	messageNonces sync.Map

	// initialRequestNonces is a single bounded set shared by every claimed
	// identity, keyed by "<identityKey>\x00<initialNonce>". Unlike the TS
	// reference, this deliberately does not track a separate per-identity
	// cap or time-based reclaim window (SessionManager.ts's
	// maxInitialRequestNoncesPerIdentity / idle-based re-claim): the shared,
	// globally-bounded FIFO cache below already rejects an exact replay and
	// bounds memory using the same overall capacity
	// (DEFAULT_MAX_INITIAL_REQUEST_NONCES), which is what BRC-103 replay
	// protection requires; the extra per-identity fairness knob is a DoS
	// refinement layered on top in TS, not a correctness requirement.
	initialRequestNonces *nonceSet

	// sessions, when non-nil, bounds how many sessions messageNonces tracks;
	// the least recently used session's cache is dropped once it is full.
	sessions *nonceSet
}

func newNonceClaims() *nonceClaims {
	return &nonceClaims{
		initialRequestNonces: newNonceSet(defaultMaxInitialRequestNonces),
	}
}

// newBoundedNonceClaims returns claims that track at most maxSessions
// sessions, for use when no SessionManager will call forgetSession.
func newBoundedNonceClaims(maxSessions int) *nonceClaims {
	nc := newNonceClaims()
	nc.sessions = newNonceSet(maxSessions)
	nc.sessions.onEvict = nc.forgetSession
	return nc
}

// ClaimMessageNonce implements NonceClaimer.
func (nc *nonceClaims) ClaimMessageNonce(sessionNonce, messageNonce string) bool {
	if sessionNonce == "" || messageNonce == "" {
		return false
	}
	v, loaded := nc.messageNonces.LoadOrStore(sessionNonce, newNonceSet(defaultMaxMessageNoncesPerSession))
	if nc.sessions != nil {
		if loaded {
			nc.sessions.touch(sessionNonce)
		} else {
			nc.sessions.claim(sessionNonce)
		}
	}
	return v.(*nonceSet).claim(messageNonce)
}

// ClaimInitialRequestNonce implements NonceClaimer.
func (nc *nonceClaims) ClaimInitialRequestNonce(identityKey, initialNonce string) bool {
	if identityKey == "" || initialNonce == "" {
		return false
	}
	return nc.initialRequestNonces.claim(identityKey + "\x00" + initialNonce)
}

// forgetSession drops a removed session's message-nonce replay cache, since
// its sessionNonce can never legitimately be presented again once the
// session itself is gone.
func (nc *nonceClaims) forgetSession(sessionNonce string) {
	if sessionNonce != "" {
		nc.messageNonces.Delete(sessionNonce)
	}
}

// nonceSet is a concurrency-safe, capacity-bounded set of previously-claimed
// keys. Once at capacity, claiming a new key evicts the single oldest
// previously-claimed key (FIFO), matching the "keep a bounded replay window
// and evict the oldest claim" strategy the TS reference documents for its
// own nonce caches.
type nonceSet struct {
	mu       sync.Mutex
	capacity int
	order    *list.List               // front = oldest claim
	elems    map[string]*list.Element // key -> its element in order
	onEvict  func(key string)         // optional; called after the lock is released
}

func newNonceSet(capacity int) *nonceSet {
	return &nonceSet{
		capacity: capacity,
		order:    list.New(),
		elems:    make(map[string]*list.Element),
	}
}

// claim atomically records key as consumed and reports whether it was new
// (true) or already claimed (false, a replay).
func (s *nonceSet) claim(key string) bool {
	evicted, ok := s.claimLocked(key)
	if evicted != "" && s.onEvict != nil {
		s.onEvict(evicted)
	}
	return ok
}

// touch marks an already-claimed key as most recently used, so FIFO eviction
// behaves as LRU for callers that touch keys on every use.
func (s *nonceSet) touch(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if elem, ok := s.elems[key]; ok {
		s.order.MoveToBack(elem)
	}
}

func (s *nonceSet) claimLocked(key string) (evicted string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.elems[key]; exists {
		return "", false
	}
	if s.capacity > 0 && len(s.elems) >= s.capacity {
		if oldest := s.order.Front(); oldest != nil {
			s.order.Remove(oldest)
			evicted = oldest.Value.(string)
			delete(s.elems, evicted)
		}
	}
	s.elems[key] = s.order.PushBack(key)
	return evicted, true
}
