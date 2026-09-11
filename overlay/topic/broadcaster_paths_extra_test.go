package topic

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/script"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
)

// TestNewBroadcasterWithResolverConfig covers the branch where a Resolver is
// supplied in the config (rather than defaulted).
func TestNewBroadcasterWithResolverConfig(t *testing.T) {
	t.Parallel()
	resolver := lookup.NewLookupResolver(&lookup.LookupResolver{})
	b, err := NewBroadcaster([]string{"tm_test"}, &BroadcasterConfig{Resolver: resolver})
	require.NoError(t, err)
	require.NotNil(t, b)
}

// TestBroadcastUsesBackgroundContext covers the plain Broadcast wrapper which
// delegates to BroadcastCtx with a background context.
func TestBroadcastUsesBackgroundContext(t *testing.T) {
	t.Parallel()
	tx := broadcastTestTx(t)
	b := &Broadcaster{
		Topics:        []string{"tm_test"},
		Facilitator:   &mockBroadcastFacilitator{steak: ackSteak("tm_test")},
		NetworkPreset: overlay.NetworkLocal,
		AckFromAll:    AckFrom{RequireAck: RequireAckNone},
		AckFromAny:    AckFrom{RequireAck: RequireAckNone},
	}

	success, failure := b.Broadcast(tx)
	require.Nil(t, failure)
	require.NotNil(t, success)
}

// TestBroadcastCtxFindInterestedHostsError covers the branch where non-local
// host discovery fails and the broadcast returns a 500 failure.
func TestBroadcastCtxFindInterestedHostsError(t *testing.T) {
	t.Parallel()
	tx := broadcastTestTx(t)
	resolver := lookup.NewLookupResolver(&lookup.LookupResolver{
		Facilitator:   &mockLookupFacilitator{err: errors.New("tracker down")},
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
	require.Equal(t, "500", failure.Code)
}

// TestBroadcastCtxAckFromAllVariants covers the remaining AckFromAll switch
// arms (RequireAckAny, RequireAckSome, and the default/unknown value).
func TestBroadcastCtxAckFromAllVariants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		ackFrom AckFrom
	}{
		{"require any", AckFrom{RequireAck: RequireAckAny}},
		{"require some", AckFrom{RequireAck: RequireAckSome, Topics: []string{"tm_test"}}},
		{"unknown value falls through to default", AckFrom{RequireAck: RequireAck(99)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tx := broadcastTestTx(t)
			b := &Broadcaster{
				Topics:        []string{"tm_test"},
				Facilitator:   &mockBroadcastFacilitator{steak: ackSteak("tm_test")},
				NetworkPreset: overlay.NetworkLocal,
				AckFromAll:    tc.ackFrom,
				AckFromAny:    AckFrom{RequireAck: RequireAckNone},
			}
			success, failure := b.BroadcastCtx(context.Background(), tx)
			require.Nil(t, failure)
			require.NotNil(t, success)
		})
	}
}

// TestBroadcastCtxAckFromAnyVariants covers the remaining AckFromAny switch
// arms (RequireAckSome, RequireAckAll, and the default/unknown value).
func TestBroadcastCtxAckFromAnyVariants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		ackFrom AckFrom
	}{
		{"require some", AckFrom{RequireAck: RequireAckSome, Topics: []string{"tm_test"}}},
		{"require all", AckFrom{RequireAck: RequireAckAll}},
		{"unknown value falls through to default", AckFrom{RequireAck: RequireAck(99)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tx := broadcastTestTx(t)
			b := &Broadcaster{
				Topics:        []string{"tm_test"},
				Facilitator:   &mockBroadcastFacilitator{steak: ackSteak("tm_test")},
				NetworkPreset: overlay.NetworkLocal,
				AckFromAll:    AckFrom{RequireAck: RequireAckNone},
				AckFromAny:    tc.ackFrom,
			}
			success, failure := b.BroadcastCtx(context.Background(), tx)
			require.Nil(t, failure)
			require.NotNil(t, success)
		})
	}
}

// TestFindInterestedHostsWrongAnswerType covers the branch where the SHIP
// tracker returns a non-output-list answer.
func TestFindInterestedHostsWrongAnswerType(t *testing.T) {
	t.Parallel()
	resolver := lookup.NewLookupResolver(&lookup.LookupResolver{
		Facilitator: &mockLookupFacilitator{answer: &lookup.LookupAnswer{
			Type:   lookup.AnswerTypeFreeform,
			Result: "not-an-output-list",
		}},
		HostOverrides: map[string][]string{"ls_ship": {"http://tracker"}},
	})
	b := &Broadcaster{
		Topics:        []string{"tm_test"},
		Resolver:      *resolver,
		NetworkPreset: overlay.NetworkMainnet,
	}

	_, err := b.FindInterestedHosts(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "not an output list")
}

// TestFindInterestedHostsNonAdminTokenSkipped covers the branch where an output
// carries a valid BEEF whose locking script is not an admin token.
func TestFindInterestedHostsNonAdminTokenSkipped(t *testing.T) {
	t.Parallel()
	// A plain locking script (not a pushdrop admin token) decodes to nil.
	plainScript := &script.Script{}
	require.NoError(t, plainScript.AppendOpcodes(script.OpTRUE))
	beef := tu.SingleOutputBeef(t, plainScript)

	resolver := lookup.NewLookupResolver(&lookup.LookupResolver{
		Facilitator: &mockLookupFacilitator{answer: &lookup.LookupAnswer{
			Type:    lookup.AnswerTypeOutputList,
			Outputs: []*lookup.OutputListItem{{Beef: beef, OutputIndex: 0}},
		}},
		HostOverrides: map[string][]string{"ls_ship": {"http://tracker"}},
	})
	b := &Broadcaster{
		Topics:        []string{"tm_test"},
		Resolver:      *resolver,
		NetworkPreset: overlay.NetworkMainnet,
	}

	hosts, err := b.FindInterestedHosts(context.Background())
	require.NoError(t, err)
	require.Empty(t, hosts)
}

// TestFindInterestedHostsWrongProtocolOrTopicSkipped covers the branch where an
// admin token is decoded but is not a SHIP advertisement for a matching topic.
func TestFindInterestedHostsWrongProtocolOrTopicSkipped(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		token []byte
	}{
		{"wrong protocol (SLAP)", tu.BuildAdminTokenBeef(t, "SLAP", "http://host", "tm_test")},
		{"wrong topic", tu.BuildAdminTokenBeef(t, "SHIP", "http://host", "tm_other")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resolver := lookup.NewLookupResolver(&lookup.LookupResolver{
				Facilitator: &mockLookupFacilitator{answer: &lookup.LookupAnswer{
					Type:    lookup.AnswerTypeOutputList,
					Outputs: []*lookup.OutputListItem{{Beef: tc.token, OutputIndex: 0}},
				}},
				HostOverrides: map[string][]string{"ls_ship": {"http://tracker"}},
			})
			b := &Broadcaster{
				Topics:        []string{"tm_test"},
				Resolver:      *resolver,
				NetworkPreset: overlay.NetworkMainnet,
			}

			hosts, err := b.FindInterestedHosts(context.Background())
			require.NoError(t, err)
			require.Empty(t, hosts)
		})
	}
}

// TestCheckAcknowledgmentFromSpecificHostsUnknownRequireAck covers the default
// arm of the per-host requirement switch (an unknown RequireAck is skipped).
func TestCheckAcknowledgmentFromSpecificHostsUnknownRequireAck(t *testing.T) {
	t.Parallel()
	b := &Broadcaster{Topics: []string{"tm_a"}}
	hostAcks := map[string]map[string]struct{}{
		"host1": {},
	}
	requirements := map[string]AckFrom{
		"host1": {RequireAck: RequireAck(99)},
	}
	require.True(t, b.checkAcknowledgmentFromSpecificHosts(hostAcks, requirements))
}
