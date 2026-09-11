package lookup

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/script"
	tu "github.com/bsv-blockchain/go-sdk/util/test_util"
)

// TestNewLookupResolverTestnetDefaultTrackers covers the branch that defaults
// SLAP trackers to the testnet list when the preset is not mainnet.
func TestNewLookupResolverTestnetDefaultTrackers(t *testing.T) {
	t.Parallel()
	r := NewLookupResolver(&LookupResolver{NetworkPreset: overlay.NetworkTestnet})
	require.Equal(t, DEFAULT_TESTNET_SLAP_TRACKERS, r.SLAPTrackers)
}

// TestQueryLocalNetworkUsesLocalhost covers the local-network host selection.
func TestQueryLocalNetworkUsesLocalhost(t *testing.T) {
	t.Parallel()
	r := &LookupResolver{
		Facilitator:     &mockFacilitator{answer: &LookupAnswer{Type: AnswerTypeOutputList}},
		HostOverrides:   map[string][]string{},
		AdditionalHosts: map[string][]string{},
		NetworkPreset:   overlay.NetworkLocal,
	}

	ans, err := r.Query(context.Background(), &LookupQuestion{Service: "ls_test"})
	require.NoError(t, err)
	require.Equal(t, AnswerTypeOutputList, ans.Type)
}

// TestQuerySlapServiceUsesTrackers covers the ls_slap branch which routes to the
// configured SLAP trackers.
func TestQuerySlapServiceUsesTrackers(t *testing.T) {
	t.Parallel()
	r := &LookupResolver{
		Facilitator:     &mockFacilitator{answer: &LookupAnswer{Type: AnswerTypeOutputList}},
		HostOverrides:   map[string][]string{},
		AdditionalHosts: map[string][]string{},
		SLAPTrackers:    []string{"http://tracker"},
	}

	ans, err := r.Query(context.Background(), &LookupQuestion{Service: "ls_slap"})
	require.NoError(t, err)
	require.Equal(t, AnswerTypeOutputList, ans.Type)
}

// TestQueryAppendsAdditionalHosts covers the branch that appends additional
// hosts on top of the resolved competent hosts.
func TestQueryAppendsAdditionalHosts(t *testing.T) {
	t.Parallel()
	r := &LookupResolver{
		Facilitator:     &mockFacilitator{answer: &LookupAnswer{Type: AnswerTypeOutputList}},
		HostOverrides:   map[string][]string{"ls_test": {"http://host-a"}},
		AdditionalHosts: map[string][]string{"ls_test": {"http://host-b"}},
	}

	ans, err := r.Query(context.Background(), &LookupQuestion{Service: "ls_test"})
	require.NoError(t, err)
	require.Equal(t, AnswerTypeOutputList, ans.Type)
}

// TestQuerySkipsNonOutputListResponse covers the branch that skips a successful
// response whose type is neither freeform nor output-list.
func TestQuerySkipsNonOutputListResponse(t *testing.T) {
	t.Parallel()
	r := newResolverWith(
		&mockFacilitator{answer: &LookupAnswer{Type: AnswerTypeFormula}},
		"ls_formula",
		[]string{"http://host-a"},
	)

	ans, err := r.Query(context.Background(), &LookupQuestion{Service: "ls_formula"})
	require.NoError(t, err)
	require.Equal(t, AnswerTypeOutputList, ans.Type)
	require.Empty(t, ans.Outputs)
}

// TestQuerySkipsInvalidBeefOutput covers the branch that logs and skips an
// output whose BEEF cannot be parsed.
func TestQuerySkipsInvalidBeefOutput(t *testing.T) {
	t.Parallel()
	r := newResolverWith(
		&mockFacilitator{answer: &LookupAnswer{
			Type:    AnswerTypeOutputList,
			Outputs: []*OutputListItem{{Beef: []byte("invalid-beef"), OutputIndex: 0}},
		}},
		"ls_badbeef",
		[]string{"http://host-a"},
	)

	ans, err := r.Query(context.Background(), &LookupQuestion{Service: "ls_badbeef"})
	require.NoError(t, err)
	require.Empty(t, ans.Outputs)
}

// TestFindCompetentHostsTrackerError covers the branch where a SLAP tracker
// query errors and produces no responses.
func TestFindCompetentHostsTrackerError(t *testing.T) {
	t.Parallel()
	r := &LookupResolver{
		Facilitator:     &mockFacilitator{err: errors.New("tracker unreachable")},
		HostOverrides:   map[string][]string{},
		AdditionalHosts: map[string][]string{},
		SLAPTrackers:    []string{"http://tracker"},
	}

	hosts, err := r.FindCompetentHosts(context.Background(), "ls_service")
	require.NoError(t, err)
	require.Empty(t, hosts)
}

// TestFindCompetentHostsSkipsInvalidBeef covers the branch that logs and skips a
// tracker output with unparseable BEEF.
func TestFindCompetentHostsSkipsInvalidBeef(t *testing.T) {
	t.Parallel()
	r := &LookupResolver{
		Facilitator: &mockFacilitator{answer: &LookupAnswer{
			Type:    AnswerTypeOutputList,
			Outputs: []*OutputListItem{{Beef: []byte("invalid-beef"), OutputIndex: 0}},
		}},
		HostOverrides:   map[string][]string{},
		AdditionalHosts: map[string][]string{},
		SLAPTrackers:    []string{"http://tracker"},
	}

	hosts, err := r.FindCompetentHosts(context.Background(), "ls_service")
	require.NoError(t, err)
	require.Empty(t, hosts)
}

// TestFindCompetentHostsOutputIndexOutOfRange covers the branch where the
// advertised output index exceeds the transaction's output count.
func TestFindCompetentHostsOutputIndexOutOfRange(t *testing.T) {
	t.Parallel()
	beef := tu.SingleOutputBeef(t, &script.Script{})
	r := &LookupResolver{
		Facilitator: &mockFacilitator{answer: &LookupAnswer{
			Type:    AnswerTypeOutputList,
			Outputs: []*OutputListItem{{Beef: beef, OutputIndex: 99}},
		}},
		HostOverrides:   map[string][]string{},
		AdditionalHosts: map[string][]string{},
		SLAPTrackers:    []string{"http://tracker"},
	}

	hosts, err := r.FindCompetentHosts(context.Background(), "ls_service")
	require.NoError(t, err)
	require.Empty(t, hosts)
}
