package topic

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// mockBroadcastFacilitator records the hosts it was asked to send to and returns
// a canned steak/error, standing in for the real HTTP facilitator.
type mockBroadcastFacilitator struct {
	steak *overlay.Steak
	err   error
	sent  []string
}

func (m *mockBroadcastFacilitator) Send(url string, _ *overlay.TaggedBEEF) (*overlay.Steak, error) {
	m.sent = append(m.sent, url)
	return m.steak, m.err
}

// broadcastTestTx builds a minimal transaction whose single input carries its
// source transaction, so AtomicBEEF succeeds.
func broadcastTestTx(t *testing.T) *transaction.Transaction {
	t.Helper()
	tx := transaction.NewTransaction()
	src := transaction.NewTransaction()
	src.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: &script.Script{}})
	tx.AddInputFromTx(src, 0, nil)
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 500, LockingScript: &script.Script{}})
	return tx
}

// ackSteak returns a steak in which every given topic admits an output.
func ackSteak(topics ...string) *overlay.Steak {
	s := overlay.Steak{}
	for _, tp := range topics {
		s[tp] = &overlay.AdmittanceInstructions{OutputsToAdmit: []uint32{0}}
	}
	return &s
}

func TestBroadcastCtxLocalSuccess(t *testing.T) {
	tx := broadcastTestTx(t)
	fac := &mockBroadcastFacilitator{steak: ackSteak("tm_test")}
	b := &Broadcaster{
		Topics:        []string{"tm_test"},
		Facilitator:   fac,
		NetworkPreset: overlay.NetworkLocal,
		AckFromAll:    AckFrom{RequireAck: RequireAckNone},
		AckFromAny:    AckFrom{RequireAck: RequireAckNone},
	}

	success, failure := b.BroadcastCtx(context.Background(), tx)
	require.Nil(t, failure)
	require.NotNil(t, success)
	require.Equal(t, tx.TxID().String(), success.Txid)
	require.Equal(t, []string{"http://localhost:8080"}, fac.sent)
}

func TestBroadcastCtxAllHostsRejected(t *testing.T) {
	tx := broadcastTestTx(t)
	b := &Broadcaster{
		Topics:        []string{"tm_test"},
		Facilitator:   &mockBroadcastFacilitator{err: errors.New("host down")},
		NetworkPreset: overlay.NetworkLocal,
		AckFromAll:    AckFrom{RequireAck: RequireAckNone},
		AckFromAny:    AckFrom{RequireAck: RequireAckNone},
	}

	success, failure := b.BroadcastCtx(context.Background(), tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Equal(t, "ERR_ALL_HOSTS_REJECTED", failure.Code)
}

func TestBroadcastCtxAtomicBEEFFailure(t *testing.T) {
	// An input with no source transaction cannot be turned into Atomic BEEF.
	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       &chainhash.Hash{},
		SourceTxOutIndex: 0,
	})

	b := &Broadcaster{
		Topics:        []string{"tm_test"},
		Facilitator:   &mockBroadcastFacilitator{steak: ackSteak("tm_test")},
		NetworkPreset: overlay.NetworkLocal,
	}

	success, failure := b.BroadcastCtx(context.Background(), tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Equal(t, "400", failure.Code)
}

func TestBroadcastCtxRequireAckFromAllFails(t *testing.T) {
	tx := broadcastTestTx(t)
	// The steak acknowledges a different topic than required.
	b := &Broadcaster{
		Topics:        []string{"tm_test"},
		Facilitator:   &mockBroadcastFacilitator{steak: ackSteak("tm_other")},
		NetworkPreset: overlay.NetworkLocal,
		AckFromAll:    AckFrom{RequireAck: RequireAckAll},
		AckFromAny:    AckFrom{RequireAck: RequireAckNone},
	}

	success, failure := b.BroadcastCtx(context.Background(), tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Equal(t, "ERR_REQUIRE_ACK_FROM_ALL_HOSTS_FAILED", failure.Code)
}

func TestBroadcastCtxRequireAckFromAllSucceeds(t *testing.T) {
	tx := broadcastTestTx(t)
	b := &Broadcaster{
		Topics:        []string{"tm_test"},
		Facilitator:   &mockBroadcastFacilitator{steak: ackSteak("tm_test")},
		NetworkPreset: overlay.NetworkLocal,
		AckFromAll:    AckFrom{RequireAck: RequireAckAll},
		AckFromAny:    AckFrom{RequireAck: RequireAckNone},
	}

	success, failure := b.BroadcastCtx(context.Background(), tx)
	require.Nil(t, failure)
	require.NotNil(t, success)
}

func TestBroadcastCtxRequireAckFromAnySucceeds(t *testing.T) {
	tx := broadcastTestTx(t)
	b := &Broadcaster{
		Topics:        []string{"tm_test"},
		Facilitator:   &mockBroadcastFacilitator{steak: ackSteak("tm_test")},
		NetworkPreset: overlay.NetworkLocal,
		AckFromAll:    AckFrom{RequireAck: RequireAckNone},
		AckFromAny:    AckFrom{RequireAck: RequireAckAny},
	}

	success, failure := b.BroadcastCtx(context.Background(), tx)
	require.Nil(t, failure)
	require.NotNil(t, success)
}

func TestBroadcastCtxRequireAckFromAnyFails(t *testing.T) {
	tx := broadcastTestTx(t)
	b := &Broadcaster{
		Topics:        []string{"tm_test"},
		Facilitator:   &mockBroadcastFacilitator{steak: ackSteak("tm_other")},
		NetworkPreset: overlay.NetworkLocal,
		AckFromAll:    AckFrom{RequireAck: RequireAckNone},
		AckFromAny:    AckFrom{RequireAck: RequireAckAny},
	}

	success, failure := b.BroadcastCtx(context.Background(), tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Equal(t, "ERR_REQUIRE_ACK_FROM_ANY_HOST_FAILED", failure.Code)
}

func TestBroadcastCtxAckFromSpecificHost(t *testing.T) {
	tx := broadcastTestTx(t)
	b := &Broadcaster{
		Topics:        []string{"tm_test"},
		Facilitator:   &mockBroadcastFacilitator{steak: ackSteak("tm_test")},
		NetworkPreset: overlay.NetworkLocal,
		AckFromHost: map[string]AckFrom{
			"http://localhost:8080": {RequireAck: RequireAckAll},
		},
	}

	success, failure := b.BroadcastCtx(context.Background(), tx)
	require.Nil(t, failure)
	require.NotNil(t, success)
}

func TestBroadcastCtxAckFromSpecificHostMissing(t *testing.T) {
	tx := broadcastTestTx(t)
	b := &Broadcaster{
		Topics:        []string{"tm_test"},
		Facilitator:   &mockBroadcastFacilitator{steak: ackSteak("tm_test")},
		NetworkPreset: overlay.NetworkLocal,
		AckFromHost: map[string]AckFrom{
			"http://unreached-host": {RequireAck: RequireAckAll},
		},
	}

	success, failure := b.BroadcastCtx(context.Background(), tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Equal(t, "ERR_REQUIRE_ACK_FROM_SPECIFIC_HOSTS_FAILED", failure.Code)
}

// mockLookupFacilitator returns a canned lookup answer, standing in for the
// SHIP tracker HTTP calls made during host discovery.
type mockLookupFacilitator struct {
	answer *lookup.LookupAnswer
	err    error
}

func (m *mockLookupFacilitator) Lookup(_ context.Context, _ string, _ *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	return m.answer, m.err
}

// adminTokenBeef hand-builds a BEEF whose single output is a pushdrop admin
// token (SHIP/SLAP advertisement) for the given domain and topic/service, so
// admintoken.Decode recognizes it without needing a wallet.
func adminTokenBeef(t *testing.T, protocol, domain, topicOrService string) []byte {
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

	tx := transaction.NewTransaction()
	src := transaction.NewTransaction()
	src.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: &script.Script{}})
	tx.AddInputFromTx(src, 0, nil)
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 500, LockingScript: s})
	beef, err := tx.BEEF()
	require.NoError(t, err)
	return beef
}

// TestBroadcastCtxDiscoversInterestedHosts covers the non-local path where the
// broadcaster resolves SHIP advertisements to find interested hosts and then
// sends to them.
func TestBroadcastCtxDiscoversInterestedHosts(t *testing.T) {
	tx := broadcastTestTx(t)

	beef := adminTokenBeef(t, "SHIP", "http://interested-host", "tm_test")
	resolver := lookup.NewLookupResolver(&lookup.LookupResolver{
		Facilitator: &mockLookupFacilitator{answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{{Beef: beef, OutputIndex: 0}},
		}},
		HostOverrides: map[string][]string{"ls_ship": {"http://tracker"}},
	})

	sendFac := &mockBroadcastFacilitator{steak: ackSteak("tm_test")}
	b := &Broadcaster{
		Topics:        []string{"tm_test"},
		Facilitator:   sendFac,
		Resolver:      *resolver,
		NetworkPreset: overlay.NetworkMainnet,
		AckFromAll:    AckFrom{RequireAck: RequireAckNone},
		AckFromAny:    AckFrom{RequireAck: RequireAckNone},
	}

	success, failure := b.BroadcastCtx(context.Background(), tx)
	require.Nil(t, failure)
	require.NotNil(t, success)
	require.Equal(t, []string{"http://interested-host"}, sendFac.sent)
}

// TestBroadcastCtxNoInterestedHosts covers the branch where discovery finds no
// interested hosts.
func TestBroadcastCtxNoInterestedHosts(t *testing.T) {
	tx := broadcastTestTx(t)

	resolver := lookup.NewLookupResolver(&lookup.LookupResolver{
		Facilitator: &mockLookupFacilitator{answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{},
		}},
		HostOverrides: map[string][]string{"ls_ship": {"http://tracker"}},
	})

	b := &Broadcaster{
		Topics:        []string{"tm_test"},
		Facilitator:   &mockBroadcastFacilitator{steak: ackSteak("tm_test")},
		Resolver:      *resolver,
		NetworkPreset: overlay.NetworkMainnet,
	}

	success, failure := b.BroadcastCtx(context.Background(), tx)
	require.Nil(t, success)
	require.NotNil(t, failure)
	require.Equal(t, "ERR_NO_HOSTS_INTERESTED", failure.Code)
}
