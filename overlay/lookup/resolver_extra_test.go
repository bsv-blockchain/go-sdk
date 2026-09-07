package lookup

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// mockFacilitator returns a canned answer/error and ignores the host URL.
type mockFacilitator struct {
	answer *LookupAnswer
	err    error
}

func (m *mockFacilitator) Lookup(_ context.Context, _ string, _ *LookupQuestion) (*LookupAnswer, error) {
	return m.answer, m.err
}

// minimalBeef builds a valid BEEF whose subject transaction has one output, for
// use as an OutputListItem.
func minimalBeef(t *testing.T) []byte {
	t.Helper()
	tx := transaction.NewTransaction()
	src := transaction.NewTransaction()
	src.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: &script.Script{}})
	tx.AddInputFromTx(src, 0, nil)
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 500, LockingScript: &script.Script{}})
	beef, err := tx.BEEF()
	require.NoError(t, err)
	return beef
}

func newResolverWith(fac Facilitator, service string, hosts []string) *LookupResolver {
	return &LookupResolver{
		Facilitator:     fac,
		HostOverrides:   map[string][]string{service: hosts},
		AdditionalHosts: map[string][]string{},
	}
}

// TestQueryOutputListAggregation covers the output-list aggregation path: two
// hosts returning the same output are de-duplicated to one.
func TestQueryOutputListAggregation(t *testing.T) {
	beef := minimalBeef(t)
	fac := &mockFacilitator{answer: &LookupAnswer{
		Type:    AnswerTypeOutputList,
		Outputs: []*OutputListItem{{Beef: beef, OutputIndex: 0}},
	}}
	r := newResolverWith(fac, "ls_test", []string{"http://host-a", "http://host-b"})

	ans, err := r.Query(context.Background(), &LookupQuestion{Service: "ls_test"})
	require.NoError(t, err)
	require.Equal(t, AnswerTypeOutputList, ans.Type)
	require.Len(t, ans.Outputs, 1)
}

// TestQueryFreeform covers the freeform short-circuit path.
func TestQueryFreeform(t *testing.T) {
	fac := &mockFacilitator{answer: &LookupAnswer{Type: AnswerTypeFreeform, Result: "hello"}}
	r := newResolverWith(fac, "ls_test", []string{"http://host-a"})

	ans, err := r.Query(context.Background(), &LookupQuestion{Service: "ls_test"})
	require.NoError(t, err)
	require.Equal(t, AnswerTypeFreeform, ans.Type)
	require.Equal(t, "hello", ans.Result)
}

// TestQueryNoSuccessfulResponses covers the branch where every host errors.
func TestQueryNoSuccessfulResponses(t *testing.T) {
	fac := &mockFacilitator{err: errors.New("host unavailable")}
	r := newResolverWith(fac, "ls_test", []string{"http://host-a"})

	_, err := r.Query(context.Background(), &LookupQuestion{Service: "ls_test"})
	require.ErrorContains(t, err, "no-successful-responses")
}

// TestQueryNoCompetentHosts covers the fall-through to FindCompetentHosts when
// there are no host overrides and no SLAP trackers.
func TestQueryNoCompetentHosts(t *testing.T) {
	r := &LookupResolver{
		Facilitator:     &mockFacilitator{answer: &LookupAnswer{Type: AnswerTypeOutputList}},
		HostOverrides:   map[string][]string{},
		AdditionalHosts: map[string][]string{},
		SLAPTrackers:    []string{},
	}

	_, err := r.Query(context.Background(), &LookupQuestion{Service: "ls_unknown"})
	require.ErrorContains(t, err, "no-competent-hosts")
}

// TestFindCompetentHostsSkipsNonOutputList covers FindCompetentHosts when a
// tracker returns a non-output-list answer: it is skipped and no hosts result.
func TestFindCompetentHostsSkipsNonOutputList(t *testing.T) {
	r := &LookupResolver{
		Facilitator:     &mockFacilitator{answer: &LookupAnswer{Type: AnswerTypeFreeform}},
		HostOverrides:   map[string][]string{},
		AdditionalHosts: map[string][]string{},
		SLAPTrackers:    []string{"http://tracker-a"},
	}

	hosts, err := r.FindCompetentHosts(context.Background(), "ls_service")
	require.NoError(t, err)
	require.Empty(t, hosts)
}
