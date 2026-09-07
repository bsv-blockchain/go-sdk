package tu

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// RoundTripFunc adapts a plain function to an http.RoundTripper so a test can
// feed canned responses to the process-global http.DefaultTransport that
// http.DefaultClient (and any &http.Client{} with a nil Transport) falls back to.
type RoundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip implements http.RoundTripper.
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// WithStubTransport swaps http.DefaultTransport for fn for the duration of the
// test and restores the previous transport via t.Cleanup. It lets a test drive
// the real nil-Client -> http.DefaultClient fallback path without touching the
// network.
//
// Because it mutates a process-global, tests that call it MUST NOT call
// t.Parallel().
func WithStubTransport(t *testing.T, fn RoundTripFunc) {
	t.Helper()
	prev := http.DefaultTransport
	http.DefaultTransport = fn
	t.Cleanup(func() { http.DefaultTransport = prev })
}

// WithUnreachableTransport makes every outbound request fail immediately,
// standing in for "no server reachable" without waiting on real network
// timeouts. Like WithStubTransport, it must not be used with t.Parallel().
func WithUnreachableTransport(t *testing.T) {
	t.Helper()
	WithStubTransport(t, func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network disabled in unit tests")
	})
}

// BuildAdminTokenBeef hand-builds a BEEF whose single output is a pushdrop
// overlay admin token (a SHIP or SLAP advertisement) for the given protocol,
// domain and topic/service. It needs no wallet, so overlay resolver/broadcaster
// tests can exercise host discovery deterministically.
func BuildAdminTokenBeef(t testing.TB, protocol, domain, topicOrService string) []byte {
	t.Helper()
	priv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	pub := priv.PubKey().Compressed()

	s := &script.Script{}
	require.NoError(t, s.AppendPushData(pub)) // locking public key
	require.NoError(t, s.AppendOpcodes(script.OpCHECKSIG))
	require.NoError(t, s.AppendPushData([]byte(protocol)))       // field 0: protocol
	require.NoError(t, s.AppendPushData(pub))                    // field 1: identity key
	require.NoError(t, s.AppendPushData([]byte(domain)))         // field 2: domain
	require.NoError(t, s.AppendPushData([]byte(topicOrService))) // field 3: topic/service
	require.NoError(t, s.AppendOpcodes(script.Op2DROP))
	require.NoError(t, s.AppendOpcodes(script.Op2DROP))

	return SingleOutputBeef(t, s)
}

// SingleOutputBeef wraps lockingScript in a BEEF whose subject transaction has
// one input (carrying its source transaction, so BEEF serialization succeeds)
// and a single output using lockingScript.
func SingleOutputBeef(t testing.TB, lockingScript *script.Script) []byte {
	t.Helper()
	tx := transaction.NewTransaction()
	src := transaction.NewTransaction()
	src.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: &script.Script{}})
	tx.AddInputFromTx(src, 0, nil)
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 500, LockingScript: lockingScript})
	beef, err := tx.BEEF()
	require.NoError(t, err)
	return beef
}
