package auth

import (
	"sync"
	"testing"
)

// TestNonceSetClaim pins the basic claim-once semantics of nonceSet: a fresh
// key is claimed (true), and re-claiming the same key reports a replay
// (false) without evicting anything.
func TestNonceSetClaim(t *testing.T) {
	s := newNonceSet(10)

	if !s.claim("a") {
		t.Fatal("expected first claim of a fresh key to succeed")
	}
	if s.claim("a") {
		t.Fatal("expected re-claiming an already-claimed key to fail")
	}
	if !s.claim("b") {
		t.Fatal("expected first claim of a different fresh key to succeed")
	}
}

// TestNonceSetBoundedEviction pins the bounded-memory guarantee: once a
// nonceSet is at capacity, claiming a new key evicts the single oldest
// previously-claimed key (FIFO), matching the "keep a bounded replay window
// and evict the oldest claim" strategy the TS reference documents.
func TestNonceSetBoundedEviction(t *testing.T) {
	s := newNonceSet(3)

	for _, k := range []string{"1", "2", "3"} {
		if !s.claim(k) {
			t.Fatalf("expected claim(%q) to succeed while under capacity", k)
		}
	}
	if len(s.elems) != 3 {
		t.Fatalf("expected 3 tracked claims, got %d", len(s.elems))
	}

	// At capacity: claiming "4" must evict "1" (the oldest), not any other
	// entry, leaving {2, 3, 4} tracked.
	if !s.claim("4") {
		t.Fatal("expected claim(4) to succeed by evicting the oldest entry")
	}
	if len(s.elems) != 3 {
		t.Fatalf("expected capacity to stay bounded at 3, got %d", len(s.elems))
	}
	if s.claim("2") {
		t.Fatal("expected \"2\" to still be tracked (not evicted) and reject a re-claim")
	}
	if s.claim("3") {
		t.Fatal("expected \"3\" to still be tracked (not evicted) and reject a re-claim")
	}
	if s.claim("4") {
		t.Fatal("expected \"4\" to still be tracked (not evicted) and reject a re-claim")
	}
	if !s.claim("1") {
		t.Fatal("expected \"1\" to have been evicted, so re-claiming it should succeed")
	}
}

// TestNonceSetConcurrentClaimSameKey drives many goroutines racing to claim
// the exact same key and asserts exactly one wins. Run with -race.
func TestNonceSetConcurrentClaimSameKey(t *testing.T) {
	const attempts = 200
	s := newNonceSet(1000)

	var wg sync.WaitGroup
	successes := make([]bool, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			successes[i] = s.claim("shared-key")
		}(i)
	}
	wg.Wait()

	won := 0
	for _, ok := range successes {
		if ok {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("expected exactly 1 of %d concurrent claims of the same key to succeed, got %d", attempts, won)
	}
}

// TestDefaultSessionManagerNonceClaimer exercises DefaultSessionManager's
// NonceClaimer implementation end to end (both message and initial-request
// nonce claims), and confirms RemoveSession forgets a session's message
// nonce cache.
func TestDefaultSessionManagerNonceClaimer(t *testing.T) {
	sm := NewSessionManager()
	var _ NonceClaimer = sm

	if !sm.ClaimMessageNonce("session-1", "nonce-a") {
		t.Fatal("expected first claim to succeed")
	}
	if sm.ClaimMessageNonce("session-1", "nonce-a") {
		t.Fatal("expected replay of the same (session, nonce) pair to fail")
	}
	if !sm.ClaimMessageNonce("session-1", "nonce-b") {
		t.Fatal("expected a different nonce on the same session to succeed")
	}
	if !sm.ClaimMessageNonce("session-2", "nonce-a") {
		t.Fatal("expected the same nonce string on a different session to succeed (scoped per session)")
	}

	if sm.ClaimMessageNonce("", "nonce-a") {
		t.Fatal("expected an empty sessionNonce to be rejected")
	}
	if sm.ClaimMessageNonce("session-1", "") {
		t.Fatal("expected an empty messageNonce to be rejected")
	}

	if !sm.ClaimInitialRequestNonce("identity-1", "initial-a") {
		t.Fatal("expected first initial-request claim to succeed")
	}
	if sm.ClaimInitialRequestNonce("identity-1", "initial-a") {
		t.Fatal("expected replay of the same (identityKey, initialNonce) pair to fail")
	}
	if !sm.ClaimInitialRequestNonce("identity-2", "initial-a") {
		t.Fatal("expected the same initialNonce string for a different identity to succeed")
	}

	// RemoveSession must forget that session's message-nonce cache, so a
	// later session that happens to reuse the same sessionNonce string isn't
	// permanently blocked.
	sm.RemoveSession(&PeerSession{SessionNonce: "session-1"})
	if !sm.ClaimMessageNonce("session-1", "nonce-a") {
		t.Fatal("expected a fresh session reusing sessionNonce \"session-1\" to be able to claim \"nonce-a\" again")
	}
}

// TestBoundedNonceClaimsEvictsOldestSession pins the Peer-owned fallback's
// memory bound: once it tracks maxSessions sessions, a new session evicts the
// least recently used session's message-nonce cache.
func TestBoundedNonceClaimsEvictsOldestSession(t *testing.T) {
	nc := newBoundedNonceClaims(2)

	if !nc.ClaimMessageNonce("s1", "n") || !nc.ClaimMessageNonce("s2", "n") {
		t.Fatal("expected first claims in two sessions to succeed")
	}
	if nc.ClaimMessageNonce("s2", "n") {
		t.Fatal("expected a replay within a tracked session to be rejected")
	}
	if !nc.ClaimMessageNonce("s3", "n") {
		t.Fatal("expected the first claim in a third session to succeed")
	}
	if _, ok := nc.messageNonces.Load("s1"); ok {
		t.Fatal("expected the oldest session's cache to be evicted")
	}
	if _, ok := nc.messageNonces.Load("s2"); !ok {
		t.Fatal("expected the newer session's cache to be kept")
	}
}

// TestBoundedNonceClaimsKeepsActiveSession proves eviction is least recently
// used: a session that keeps claiming nonces survives churn from new sessions
// and still rejects replays.
func TestBoundedNonceClaimsKeepsActiveSession(t *testing.T) {
	nc := newBoundedNonceClaims(2)

	if !nc.ClaimMessageNonce("active", "n1") || !nc.ClaimMessageNonce("idle", "n1") {
		t.Fatal("expected first claims to succeed")
	}
	if !nc.ClaimMessageNonce("active", "n2") {
		t.Fatal("expected a new nonce in the active session to succeed")
	}
	if !nc.ClaimMessageNonce("new", "n1") {
		t.Fatal("expected the first claim in a new session to succeed")
	}
	if _, ok := nc.messageNonces.Load("idle"); ok {
		t.Fatal("expected the least recently used session to be evicted")
	}
	if nc.ClaimMessageNonce("active", "n1") {
		t.Fatal("expected the active session to still reject a replay")
	}
}
