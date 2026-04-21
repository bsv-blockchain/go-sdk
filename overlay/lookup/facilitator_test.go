package lookup

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/testdata"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/stretchr/testify/require"
)

const (
	contentTypeJSON   = "application/json"
	headerContentType = "Content-Type"
)

func TestHTTPSOverlayLookupFacilitatorSuccess(t *testing.T) {
	expectedAnswer := &LookupAnswer{
		Type:   AnswerTypeFreeform,
		Result: "test-result",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/lookup", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, contentTypeJSON, r.Header.Get(headerContentType))

		// Decode the incoming question to verify it was sent correctly.
		var q LookupQuestion
		err := json.NewDecoder(r.Body).Decode(&q)
		require.NoError(t, err)
		require.Equal(t, "ls_slap", q.Service)

		w.Header().Set(headerContentType, contentTypeJSON)
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

func TestHTTPSOverlayLookupFacilitatorNonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	f := &HTTPSOverlayLookupFacilitator{Client: http.DefaultClient}
	question := &LookupQuestion{Service: "ls_slap"}

	_, err := f.Lookup(context.Background(), server.URL, question)
	require.Error(t, err)
}

func TestHTTPSOverlayLookupFacilitatorServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	f := &HTTPSOverlayLookupFacilitator{Client: http.DefaultClient}
	question := &LookupQuestion{Service: "ls_slap"}

	_, err := f.Lookup(context.Background(), server.URL, question)
	require.Error(t, err)
}

func TestHTTPSOverlayLookupFacilitatorBadURL(t *testing.T) {
	f := &HTTPSOverlayLookupFacilitator{Client: http.DefaultClient}
	question := &LookupQuestion{Service: "ls_slap"}

	_, err := f.Lookup(context.Background(), "http://127.0.0.1:0", question)
	require.Error(t, err)
}

func TestHTTPSOverlayLookupFacilitatorInvalidResponseBody(t *testing.T) {
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

func TestHTTPSOverlayLookupFacilitatorOutputListAnswer(t *testing.T) {
	expectedAnswer := &LookupAnswer{
		Type: AnswerTypeOutputList,
		Outputs: []*OutputListItem{
			{Beef: []byte{0x01, 0x02}, OutputIndex: 0},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(headerContentType, contentTypeJSON)
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

// buildBinaryLookupResponse constructs a binary octet-stream lookup response.
// It uses the Issue96BeefHex fixture which is a complete BEEF with a known tx chain.
func buildBinaryLookupResponse(t *testing.T, outputIndex uint32, contextData []byte) []byte {
	t.Helper()

	beefBytes, err := hex.DecodeString(testdata.Issue96BeefHex)
	require.NoError(t, err)

	beef, err := transaction.NewBeefFromBytes(beefBytes)
	require.NoError(t, err)
	require.NotNil(t, beef.NewestTxID)

	rawTxid, err := hex.DecodeString(beef.NewestTxID.String())
	require.NoError(t, err)

	w := &util.Writer{}
	w.WriteVarInt(1)
	w.WriteBytes(rawTxid)
	w.WriteVarInt(uint64(outputIndex))
	w.WriteVarInt(uint64(len(contextData)))
	if len(contextData) > 0 {
		w.WriteBytes(contextData)
	}
	w.WriteBytes(beefBytes)
	return w.Buf
}

func TestHTTPSOverlayLookupFacilitatorXAggregationHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "yes", r.Header.Get("X-Aggregation"))
		w.Header().Set(headerContentType, contentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(&LookupAnswer{Type: AnswerTypeFreeform})
	}))
	defer server.Close()

	f := &HTTPSOverlayLookupFacilitator{Client: http.DefaultClient}
	_, err := f.Lookup(context.Background(), server.URL, &LookupQuestion{Service: "ls_slap"})
	require.NoError(t, err)
}

func TestHTTPSOverlayLookupFacilitatorBinaryResponse(t *testing.T) {
	outputIndex := uint32(1) // tx has 2 outputs; index 1 is the P2PKH
	body := buildBinaryLookupResponse(t, outputIndex, nil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(headerContentType, "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer server.Close()

	f := &HTTPSOverlayLookupFacilitator{Client: http.DefaultClient}
	answer, err := f.Lookup(context.Background(), server.URL, &LookupQuestion{Service: "ls_uhrp"})
	require.NoError(t, err)
	require.Equal(t, AnswerTypeOutputList, answer.Type)
	require.Len(t, answer.Outputs, 1)
	require.Equal(t, outputIndex, answer.Outputs[0].OutputIndex)
}

func TestHTTPSOverlayLookupFacilitatorBinaryResponseWithContext(t *testing.T) {
	contextData := []byte("some-context")
	body := buildBinaryLookupResponse(t, 0, contextData)

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set(headerContentType, "application/octet-stream")
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write(body)
	}))
	defer server.Close()

	f := &HTTPSOverlayLookupFacilitator{Client: http.DefaultClient}
	answer, err := f.Lookup(context.Background(), server.URL, &LookupQuestion{Service: "ls_uhrp"})
	require.NoError(t, err)
	require.Equal(t, AnswerTypeOutputList, answer.Type)
	require.Len(t, answer.Outputs, 1)
}

func TestParseBinaryLookupAnswerTruncated(t *testing.T) {
	// Feed only 10 bytes — should error, not panic.
	_, err := parseBinaryLookupAnswer([]byte{0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	require.Error(t, err)
}

func TestParseBinaryLookupAnswerZeroOutpoints(t *testing.T) {
	// Valid empty response: nOutpoints=0 + empty BEEF placeholder.
	// Without a real BEEF we can't do much, but zero outpoints → empty output list
	// before we even touch the BEEF bytes. Encode nOutpoints=0 then a dummy BEEF
	// that won't be parsed (we use a 4-byte invalid version to trigger NewBeefFromBytes error,
	// but since there are 0 outpoints, BEEF parsing is still attempted).
	// So just verify the function at least doesn't panic and returns a meaningful error or empty list.
	buf := make([]byte, 5)
	buf[0] = 0x00 // VarInt(0) outpoints
	binary.LittleEndian.PutUint32(buf[1:], 0xDEADBEEF) // garbage BEEF
	_, err := parseBinaryLookupAnswer(buf)
	// Either an empty list (if BEEF version check passes) or an error — no panic either way.
	_ = err
}

func TestNewLookupResolverDefaults(t *testing.T) {
	resolver := NewLookupResolver(&LookupResolver{})
	require.NotNil(t, resolver)
	require.NotNil(t, resolver.Facilitator)
	require.NotNil(t, resolver.SLAPTrackers)
	require.NotEmpty(t, resolver.SLAPTrackers)
	require.NotNil(t, resolver.HostOverrides)
	require.NotNil(t, resolver.AdditionalHosts)
}

func TestNewLookupResolverWithCustomFacilitator(t *testing.T) {
	f := &HTTPSOverlayLookupFacilitator{Client: http.DefaultClient}
	resolver := NewLookupResolver(&LookupResolver{
		Facilitator: f,
	})
	require.Equal(t, f, resolver.Facilitator)
}

func TestNewLookupResolverWithCustomTrackers(t *testing.T) {
	trackers := []string{"https://example.com"}
	resolver := NewLookupResolver(&LookupResolver{
		SLAPTrackers: trackers,
	})
	require.Equal(t, trackers, resolver.SLAPTrackers)
}

func TestNewLookupResolverWithHostOverrides(t *testing.T) {
	overrides := map[string][]string{
		"my_service": {"https://host1.example.com"},
	}
	resolver := NewLookupResolver(&LookupResolver{
		HostOverrides: overrides,
	})
	require.Equal(t, overrides, resolver.HostOverrides)
}
