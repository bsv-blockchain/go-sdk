package lookup

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHTTPSOverlayLookupFacilitator_Success(t *testing.T) {
	expectedAnswer := &LookupAnswer{
		Type:   AnswerTypeFreeform,
		Result: "test-result",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/lookup", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Decode the incoming question to verify it was sent correctly.
		var q LookupQuestion
		err := json.NewDecoder(r.Body).Decode(&q)
		require.NoError(t, err)
		require.Equal(t, "ls_slap", q.Service)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(expectedAnswer)
	}))
	defer server.Close()

	f := &HTTPSOverlayLookupFacilitator{Client: http.DefaultClient}
	question := &LookupQuestion{
		Service: "ls_slap",
		Query:   json.RawMessage(`{"service":"test"}`),
	}

	answer, err := f.Lookup(context.Background(), server.URL, question)
	require.NoError(t, err)
	require.NotNil(t, answer)
	require.Equal(t, AnswerTypeFreeform, answer.Type)
}

func TestHTTPSOverlayLookupFacilitator_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	f := &HTTPSOverlayLookupFacilitator{Client: http.DefaultClient}
	question := &LookupQuestion{Service: "ls_slap"}

	_, err := f.Lookup(context.Background(), server.URL, question)
	require.Error(t, err)
}

func TestHTTPSOverlayLookupFacilitator_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	f := &HTTPSOverlayLookupFacilitator{Client: http.DefaultClient}
	question := &LookupQuestion{Service: "ls_slap"}

	_, err := f.Lookup(context.Background(), server.URL, question)
	require.Error(t, err)
}

func TestHTTPSOverlayLookupFacilitator_BadURL(t *testing.T) {
	f := &HTTPSOverlayLookupFacilitator{Client: http.DefaultClient}
	question := &LookupQuestion{Service: "ls_slap"}

	_, err := f.Lookup(context.Background(), "http://127.0.0.1:0", question)
	require.Error(t, err)
}

func TestHTTPSOverlayLookupFacilitator_InvalidResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer server.Close()

	f := &HTTPSOverlayLookupFacilitator{Client: http.DefaultClient}
	question := &LookupQuestion{Service: "ls_slap"}

	_, err := f.Lookup(context.Background(), server.URL, question)
	require.Error(t, err)
}

func TestHTTPSOverlayLookupFacilitator_OutputListAnswer(t *testing.T) {
	expectedAnswer := &LookupAnswer{
		Type: AnswerTypeOutputList,
		Outputs: []*OutputListItem{
			{Beef: []byte{0x01, 0x02}, OutputIndex: 0},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(expectedAnswer)
	}))
	defer server.Close()

	f := &HTTPSOverlayLookupFacilitator{Client: http.DefaultClient}
	question := &LookupQuestion{Service: "ls_ship"}

	answer, err := f.Lookup(context.Background(), server.URL, question)
	require.NoError(t, err)
	require.Equal(t, AnswerTypeOutputList, answer.Type)
	require.Len(t, answer.Outputs, 1)
}

func TestNewLookupResolver_Defaults(t *testing.T) {
	resolver := NewLookupResolver(&LookupResolver{})
	require.NotNil(t, resolver)
	require.NotNil(t, resolver.Facilitator)
	require.NotNil(t, resolver.SLAPTrackers)
	require.NotEmpty(t, resolver.SLAPTrackers)
	require.NotNil(t, resolver.HostOverrides)
	require.NotNil(t, resolver.AdditionalHosts)
}

func TestNewLookupResolver_WithCustomFacilitator(t *testing.T) {
	f := &HTTPSOverlayLookupFacilitator{Client: http.DefaultClient}
	resolver := NewLookupResolver(&LookupResolver{
		Facilitator: f,
	})
	require.Equal(t, f, resolver.Facilitator)
}

func TestNewLookupResolver_WithCustomTrackers(t *testing.T) {
	trackers := []string{"https://example.com"}
	resolver := NewLookupResolver(&LookupResolver{
		SLAPTrackers: trackers,
	})
	require.Equal(t, trackers, resolver.SLAPTrackers)
}

func TestNewLookupResolver_WithHostOverrides(t *testing.T) {
	overrides := map[string][]string{
		"my_service": {"https://host1.example.com"},
	}
	resolver := NewLookupResolver(&LookupResolver{
		HostOverrides: overrides,
	})
	require.Equal(t, overrides, resolver.HostOverrides)
}
