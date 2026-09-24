// Package overlay_test runs the ts-stack overlay HTTP API conformance vectors
// (overlay/submit.json, overlay/lookup.json, overlay/topic-management.json)
// against the Go SDK's overlay client.
//
// Reference: conformance/runner/ts/dispatchers/overlay.ts and overlayHelpers.ts
// in the pinned ts-stack checkout. Those dispatchers describe an HTTP API
// contract (overlay-express); the TypeScript SDK has no client wrapper for
// most of these routes either, so both language runners validate the
// input/expected fixture SHAPES rather than driving a live server end-to-end.
//
// Where the Go SDK does ship a real client (POST /submit via
// overlay/topic.HTTPSOverlayBroadcastFacilitator, POST /lookup via
// overlay/lookup.HTTPSOverlayLookupFacilitator), this file drives that real
// client against an httptest server built from each vector so the wire shape
// (method, path, headers, status handling) is exercised, not just asserted
// against the fixture. Discovery/health/admin endpoints have no Go client at
// all -- exactly like the TS reference -- so those vectors stay structural,
// mirroring overlayHelpers.ts.
//
// MISMATCH flag (carried over from the TS dispatcher's own comment): the
// overlay-http.yaml schema names the coinstake field
// "coinstakeOutputsToRetain", while the actual @bsv/sdk client type
// (SHIPBroadcaster.ts) calls it "coinsToRetain" and rejects any other key.
// The vectors here follow the schema name. This file therefore never asserts
// equality on that particular field through the Go client's decoded struct;
// it only checks it structurally against the fixture, exactly as
// assertSteakShape does in TS.
package overlay_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/topic"
	"github.com/bsv-blockchain/go-sdk/util"
)

// ── Shared vector shapes ─────────────────────────────────────────────────────

type vectorInput struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    json.RawMessage   `json:"body"`
	BodyHex string            `json:"body_hex"`
	Topics  []string          `json:"topics"`
	Query   map[string]string `json:"query"`
}

type vectorExpected struct {
	Status      *int                   `json:"status"`
	StatusOneof []int                  `json:"status_oneof"`
	ContentType string                 `json:"content_type"`
	Body        map[string]any         `json:"body"`
	BodySchema  string                 `json:"body_schema"`
	BodyType    string                 `json:"body_type"`
	ExampleBody map[string]any         `json:"example_body"`
	Raw         map[string]interface{} `json:"-"`
}

func decodeInput(t *testing.T, v conformance.Vector) vectorInput {
	t.Helper()
	var in vectorInput
	v.DecodeInput(t, &in)
	return in
}

func decodeExpected(t *testing.T, v conformance.Vector) vectorExpected {
	t.Helper()
	var exp vectorExpected
	v.DecodeExpected(t, &exp)
	// Also decode into a generic map so we can look at fields the typed
	// struct doesn't name (e.g. "valid", per-vector ad-hoc fields).
	_ = json.Unmarshal(v.Expected, &exp.Raw)
	return exp
}

func expectedStatuses(exp vectorExpected) []int {
	if exp.Status != nil {
		return []int{*exp.Status}
	}
	return exp.StatusOneof
}

func headerLookup(headers map[string]string, key string) (string, bool) {
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

// assertHTTPStatusShape mirrors overlayHelpers.ts assertHttpStatus: whatever
// status shape the vector declares must be a well-formed HTTP status code.
func assertHTTPStatusShape(t *testing.T, exp vectorExpected) {
	t.Helper()
	statuses := expectedStatuses(exp)
	if len(statuses) == 0 {
		t.Fatalf("vector declares neither status nor status_oneof")
	}
	for _, s := range statuses {
		if s < 100 || s >= 600 {
			t.Fatalf("status %d out of HTTP range", s)
		}
	}
}

// assertErrorShape mirrors overlayHelpers.ts assertErrorShape.
func assertErrorShape(t *testing.T, body map[string]any) {
	t.Helper()
	if body["status"] != "error" {
		t.Fatalf("error body.status = %v, want %q", body["status"], "error")
	}
}

// assertSteakShape mirrors overlayHelpers.ts assertSteakShape: validates the
// STEAK's structural invariants directly against the fixture, independent of
// any specific Go struct's field names.
func assertSteakShape(t *testing.T, body map[string]any) {
	t.Helper()
	for topicName, raw := range body {
		result, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("topic %q result is not an object: %#v", topicName, raw)
		}
		admit, ok := result["outputsToAdmit"].([]any)
		if !ok {
			t.Fatalf("topic %q missing outputsToAdmit array: %#v", topicName, result)
		}
		for _, idx := range admit {
			n, ok := idx.(float64)
			if !ok || n < 0 {
				t.Fatalf("topic %q outputsToAdmit contains a non-negative-number: %#v", topicName, idx)
			}
		}
		if raw, ok := result["coinstakeOutputsToRetain"]; ok {
			retain, ok := raw.([]any)
			if !ok {
				t.Fatalf("topic %q coinstakeOutputsToRetain is not an array: %#v", topicName, raw)
			}
			for _, idx := range retain {
				n, ok := idx.(float64)
				if !ok || n < 0 {
					t.Fatalf("topic %q coinstakeOutputsToRetain contains a non-negative-number: %#v", topicName, idx)
				}
			}
		}
	}
}

func decodedTopics(in vectorInput) []string {
	if len(in.Topics) > 0 {
		return in.Topics
	}
	if raw, ok := headerLookup(in.Headers, "x-topics"); ok {
		var topics []string
		if err := json.Unmarshal([]byte(raw), &topics); err == nil {
			return topics
		}
	}
	return []string{"tm_ship"}
}

// ── overlay.submit ───────────────────────────────────────────────────────────

func TestOverlaySubmit(t *testing.T) {
	f := conformance.Load(t, "overlay/submit.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		in := decodeInput(t, v)
		exp := decodeExpected(t, v)
		assertHTTPStatusShape(t, exp)

		if in.Method != "" {
			if in.Method != http.MethodPost {
				t.Fatalf("vector input.method = %q, want POST", in.Method)
			}
		}
		if in.Path != "" && in.Path != "/submit" {
			t.Fatalf("vector input.path = %q, want /submit", in.Path)
		}

		bodyBytes, err := hex.DecodeString(in.BodyHex)
		if err != nil {
			t.Fatalf("decode body_hex: %v", err)
		}
		topics := decodedTopics(in)

		wantStatus := expectedStatuses(exp)[0]

		var gotReq *http.Request
		var gotBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotReq = r
			gotBody, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(wantStatus)
			_ = json.NewEncoder(w).Encode(exp.Body)
		}))
		defer server.Close()

		fac := &topic.HTTPSOverlayBroadcastFacilitator{Client: http.DefaultClient}
		steak, sendErr := fac.Send(server.URL, &overlay.TaggedBEEF{Beef: bodyBytes, Topics: topics})

		// Real client request-shape checks (method/path/headers), regardless
		// of the declared status: the Go client's own wire behavior must
		// always be correct, even for vectors that document a server-side
		// rejection.
		if gotReq == nil {
			t.Fatalf("server never received a request")
		}
		if gotReq.Method != http.MethodPost {
			t.Errorf("client sent method %q, want POST", gotReq.Method)
		}
		if gotReq.URL.Path != "/submit" {
			t.Errorf("client sent path %q, want /submit", gotReq.URL.Path)
		}
		if ct := gotReq.Header.Get("Content-Type"); ct != "application/octet-stream" {
			t.Errorf("client sent Content-Type %q, want application/octet-stream", ct)
		}
		var sentTopics []string
		if err := json.Unmarshal([]byte(gotReq.Header.Get("X-Topics")), &sentTopics); err != nil {
			t.Errorf("client's X-Topics header is not valid JSON: %q", gotReq.Header.Get("X-Topics"))
		} else if len(sentTopics) != len(topics) {
			t.Errorf("client's X-Topics = %v, want %v", sentTopics, topics)
		}
		if !bytes.Equal(gotBody, bodyBytes) {
			t.Errorf("client sent body of length %d, want %d", len(gotBody), len(bodyBytes))
		}

		if wantStatus == http.StatusOK {
			if sendErr != nil {
				t.Fatalf("facilitator.Send returned an error for a 200 response: %v", sendErr)
			}
			if steak == nil {
				t.Fatalf("facilitator.Send returned a nil steak for a 200 response")
			}
			assertSteakShape(t, exp.Body)
			for topicName, raw := range exp.Body {
				result := raw.(map[string]any)
				admit, ok := (*steak)[topicName]
				if !ok {
					t.Errorf("decoded steak missing topic %q", topicName)
					continue
				}
				wantAdmit := result["outputsToAdmit"].([]any)
				if len(admit.OutputsToAdmit) != len(wantAdmit) {
					t.Errorf("topic %q: decoded OutputsToAdmit = %v, want %d entries", topicName, admit.OutputsToAdmit, len(wantAdmit))
				}
			}
			return
		}

		// Error path: the client must surface a non-nil error and never try
		// to interpret the body as a STEAK.
		if sendErr == nil {
			t.Fatalf("facilitator.Send returned no error for status %d", wantStatus)
		}
		var httpErr *util.HTTPError
		if !errors.As(sendErr, &httpErr) {
			t.Fatalf("facilitator.Send error is %T, want *util.HTTPError", sendErr)
		}
		if httpErr.StatusCode != wantStatus {
			t.Errorf("HTTPError.StatusCode = %d, want %d", httpErr.StatusCode, wantStatus)
		}
		assertErrorShape(t, exp.Body)
		if bodyRaw, ok := exp.Raw["body"].(map[string]any); ok {
			if want, ok := bodyRaw["message_type"]; ok && want != "string" {
				t.Errorf("message_type schema note = %v, want %q", want, "string")
			}
		}
	})
}
