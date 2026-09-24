package overlay_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/util"
)

// assertLookupAnswerShape mirrors overlayHelpers.ts assertLookupAnswerShape /
// assertLookupAnswerOutputList / assertLookupAnswerFreeform.
func assertLookupAnswerShape(t *testing.T, body map[string]any) {
	t.Helper()
	switch body["type"] {
	case "output-list":
		outputs, ok := body["outputs"].([]any)
		if !ok {
			t.Fatalf("output-list answer missing outputs array: %#v", body)
		}
		for _, raw := range outputs {
			o, ok := raw.(map[string]any)
			if !ok {
				t.Fatalf("output-list entry is not an object: %#v", raw)
			}
			if _, ok := o["beef"].([]any); !ok {
				t.Fatalf("output-list entry missing beef array: %#v", o)
			}
			if _, ok := o["outputIndex"].(float64); !ok {
				t.Fatalf("output-list entry missing numeric outputIndex: %#v", o)
			}
		}
	case "freeform":
		// outputs/result are optional per the schema; nothing further to check.
	case nil:
		// untyped body (e.g. error responses use a different shape).
	default:
		if _, ok := body["type"].(string); !ok {
			t.Fatalf("answer type is not a string: %#v", body["type"])
		}
	}
}

// TestOverlayLookup covers the POST /lookup vectors, driving the real Go
// lookup facilitator against an httptest server, plus the GET discovery
// endpoints (/listTopicManagers, /listLookupServiceProviders,
// /getDocumentationForTopicManager), which have no Go client and are checked
// structurally exactly as the TS dispatcher does.
func TestOverlayLookup(t *testing.T) {
	f := conformance.Load(t, "overlay/lookup.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		in := decodeInput(t, v)
		exp := decodeExpected(t, v)
		assertHTTPStatusShape(t, exp)

		method := in.Method
		if method == "" {
			method = http.MethodPost
		}

		if method == http.MethodGet {
			dispatchLookupGet(t, in, exp)
			return
		}

		dispatchLookupPost(t, in, exp)
	})
}

func dispatchLookupGet(t *testing.T, in vectorInput, exp vectorExpected) {
	t.Helper()
	status := 200
	if s := expectedStatuses(exp); len(s) > 0 {
		status = s[0]
	}

	switch in.Path {
	case "/listTopicManagers", "/listLookupServiceProviders":
		if status != http.StatusOK {
			t.Errorf("discovery endpoint %s expected 200, vector says %d", in.Path, status)
		}
		if exp.BodySchema == "" {
			t.Errorf("%s: expected.body_schema missing", in.Path)
		}
		for key, raw := range exp.ExampleBody {
			info, ok := raw.(map[string]any)
			if !ok {
				t.Fatalf("%s: example_body[%q] is not an object: %#v", in.Path, key, raw)
			}
			if name, ok := info["name"]; ok {
				if _, ok := name.(string); !ok {
					t.Errorf("%s: example_body[%q].name is not a string", in.Path, key)
				}
			}
			if desc, ok := info["shortDescription"]; ok {
				if _, ok := desc.(string); !ok {
					t.Errorf("%s: example_body[%q].shortDescription is not a string", in.Path, key)
				}
			}
		}
	case "/getDocumentationForTopicManager":
		if status == http.StatusOK {
			if exp.ContentType != "" && exp.ContentType != "text/markdown" {
				t.Errorf("documentation endpoint content_type = %q, want text/markdown", exp.ContentType)
			}
			if exp.BodyType != "" && exp.BodyType != "string" {
				t.Errorf("documentation endpoint body_type = %q, want string", exp.BodyType)
			}
		} else {
			if status != http.StatusBadRequest {
				t.Errorf("documentation endpoint error status = %d, want 400", status)
			}
			if exp.Body != nil {
				assertErrorShape(t, exp.Body)
			}
		}
	default:
		// Unknown GET path under lookup: only the status shape matters.
	}
}

func dispatchLookupPost(t *testing.T, in vectorInput, exp vectorExpected) {
	t.Helper()
	if in.Path != "" && in.Path != "/lookup" {
		t.Fatalf("vector input.path = %q, want /lookup", in.Path)
	}

	// Binary-aggregation vectors document the wire format but neither
	// runtime actually round-trips a live payload through the SDK for them
	// (see assertLookupBinaryResponse in overlayHelpers.ts) - validate the
	// documented shape only.
	if agg, ok := headerLookup(in.Headers, "x-aggregation"); ok && agg == "yes" {
		if exp.ContentType != "" && exp.ContentType != "application/octet-stream" {
			t.Errorf("aggregated lookup content_type = %q, want application/octet-stream", exp.ContentType)
		}
		return
	}

	var reqBody map[string]any
	_ = json.Unmarshal(in.Body, &reqBody)
	service, _ := reqBody["service"].(string)
	if service == "" {
		service = "ls_ship" // malformed-input vectors still need a syntactically valid question to send.
	}
	query, ok := reqBody["query"]
	queryRaw := json.RawMessage(`{}`)
	if ok && query != nil {
		if marshaled, err := json.Marshal(query); err == nil {
			queryRaw = marshaled
		}
	}

	wantStatus := 200
	if s := expectedStatuses(exp); len(s) > 0 {
		wantStatus = s[0]
	}

	var gotReq *http.Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReq = r
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(wantStatus)
		_ = json.NewEncoder(w).Encode(exp.Body)
	}))
	defer server.Close()

	fac := &lookup.HTTPSOverlayLookupFacilitator{Client: http.DefaultClient}
	answer, err := fac.Lookup(t.Context(), server.URL, &lookup.LookupQuestion{Service: service, Query: queryRaw})

	if gotReq == nil {
		t.Fatalf("server never received a request")
	}
	if gotReq.Method != http.MethodPost {
		t.Errorf("client sent method %q, want POST", gotReq.Method)
	}
	if gotReq.URL.Path != "/lookup" {
		t.Errorf("client sent path %q, want /lookup", gotReq.URL.Path)
	}
	if ct := gotReq.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("client sent Content-Type %q, want application/json", ct)
	}

	if wantStatus == http.StatusOK {
		if err != nil {
			t.Fatalf("facilitator.Lookup returned an error for a 200 response: %v", err)
		}
		if answer == nil {
			t.Fatalf("facilitator.Lookup returned a nil answer for a 200 response")
		}
		assertLookupAnswerShape(t, exp.Body)
		if wantType, ok := exp.Body["type"].(string); ok && string(answer.Type) != wantType {
			t.Errorf("decoded answer.Type = %q, want %q", answer.Type, wantType)
		}
		if wantType, _ := exp.Body["type"].(string); wantType == "output-list" {
			wantOutputs, _ := exp.Body["outputs"].([]any)
			if len(answer.Outputs) != len(wantOutputs) {
				t.Errorf("decoded answer has %d outputs, want %d", len(answer.Outputs), len(wantOutputs))
			}
		}
		return
	}

	if err == nil {
		t.Fatalf("facilitator.Lookup returned no error for status %d", wantStatus)
	}
	var httpErr *util.HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("facilitator.Lookup error is %T, want *util.HTTPError", err)
	}
	if httpErr.StatusCode != wantStatus {
		t.Errorf("HTTPError.StatusCode = %d, want %d", httpErr.StatusCode, wantStatus)
	}
	if exp.Body != nil {
		assertErrorShape(t, exp.Body)
	}
}
