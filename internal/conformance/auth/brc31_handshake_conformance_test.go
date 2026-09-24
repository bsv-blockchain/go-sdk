package auth_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/authpayload"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/testcertificates"
)

// ── Part A: dispatch mirror ─────────────────────────────────────────────────
//
// dispatchBRC31Handshake below is a line-for-line port of
// conformance/runner/ts/dispatchers/auth.ts's dispatchBRC31Handshake and its
// helpers. Every one of those helpers (besides dispatchInitialRequest and
// dispatchResponsePreimage) checks the vector's own recorded input/expected
// shape rather than exercising a live server, exactly as the TS reference
// dispatcher does — no HTTP server is required there either, and Peer/HTTP
// emission is instead exercised for real below, in Part B and Part C.

func TestBRC31HandshakeConformance(t *testing.T) {
	file := conformance.Load(t, "auth/brc31-handshake.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		input := decodeGenericObject(t, v.ID, v.Input)
		expected := decodeGenericObject(t, v.ID, v.Expected)
		dispatchBRC31Handshake(t, v.ID, input, expected)
	})
}

func dispatchBRC31Handshake(t *testing.T, vectorID string, input, expected map[string]any) {
	t.Helper()

	if getBoolField(input, "http_response_preimage") {
		dispatchResponsePreimage(t, vectorID, input, expected)
		return
	}

	path, _ := input["path"].(string)
	schemaCheck := getBoolField(input, "_schema_check")
	method, _ := input["method"].(string)

	if schemaCheck {
		if _, ok := input["messageType"]; ok {
			dispatchAuthMessageSchema(t, vectorID, input, expected)
			return
		}
		if _, ok := input["valid_examples"]; ok {
			dispatchPubKeyHexFormat(t, vectorID, input, expected)
			return
		}
	}
	if _, ok := input["requestId_example"]; ok {
		dispatchRequestIDFormat(t, vectorID, input, expected)
		return
	}
	if _, ok := input["requestId_length_bytes"]; ok {
		dispatchRequestIDFormat(t, vectorID, input, expected)
		return
	}

	if path == "/.well-known/auth" && dispatchWellKnownAuth(t, vectorID, input, expected) {
		return
	}

	isProtectedResource := path == "/api/resource" || path == "/api/public-resource" || path == "/sendMessage" ||
		(method != "" && path != "" && path != "/.well-known/auth")
	if isProtectedResource && dispatchProtectedResource(t, vectorID, input, expected) {
		return
	}

	t.Fatalf("%s: vector shape not recognised by the dispatcher (coverage gap)", vectorID)
}

func dispatchWellKnownAuth(t *testing.T, vectorID string, input, expected map[string]any) bool {
	t.Helper()
	body, _ := input["body"].(map[string]any)
	messageType, _ := body["messageType"].(string)
	status, hasStatus := toFloat(expected["status"])

	if hasStatus && status == 401 && messageType == "initialRequest" {
		dispatchMissingFieldError(t, vectorID, expected)
		return true
	}
	if hasStatus && status == 408 {
		dispatchCertificateTimeout(t, vectorID, expected)
		return true
	}
	if _, ok := expected["response_body_includes"]; ok {
		dispatchRequestedCertificatesBody(t, vectorID, expected)
		return true
	}
	if _, ok := expected["body_shape"]; ok && messageType == "initialRequest" {
		dispatchInitialRequest(t, vectorID, input, expected)
		return true
	}
	if hasStatus && status == 401 {
		if _, ok := input["_scenario"]; ok {
			dispatchReplayPrevention(t, vectorID, expected)
			return true
		}
	}
	return false
}

func dispatchProtectedResource(t *testing.T, vectorID string, input, expected map[string]any) bool {
	t.Helper()
	status, hasStatus := toFloat(expected["status"])
	headers, _ := input["headers"].(map[string]any)
	body, _ := expected["body"].(map[string]any)

	if _, ok := expected["req_auth_identity_key"]; ok {
		dispatchAllowUnauthenticated(t, vectorID, expected)
		return true
	}
	if hasStatus && status == 401 {
		if _, hasSig := headers["x-bsv-auth-signature"]; !hasSig {
			dispatchMissingSignatureError(t, vectorID, expected)
			return true
		}
	}
	if code, _ := body["code"].(string); hasStatus && status == 401 && code == "ERR_AUTH_FAILED" {
		dispatchBadSignatureError(t, vectorID, expected)
		return true
	}
	if hasStatus && status == 500 {
		dispatchResponseSigningFailure(t, vectorID, expected)
		return true
	}
	if _, ok := expected["response_headers_required"]; ok {
		dispatchGeneralRequestHeaders(t, vectorID, expected)
		return true
	}
	return false
}

// dispatchInitialRequest mirrors auth.ts's dispatchInitialRequest: a
// structural check of the vector's own recorded HTTP request/response
// fixture (auth.brc31-handshake.1, .2).
func dispatchInitialRequest(t *testing.T, vectorID string, input, expected map[string]any) {
	t.Helper()

	if input["method"] != "POST" {
		t.Errorf("%s: method = %v, want POST", vectorID, input["method"])
	}
	if input["path"] != "/.well-known/auth" {
		t.Errorf("%s: path = %v, want /.well-known/auth", vectorID, input["path"])
	}

	headers, _ := input["headers"].(map[string]any)
	lowerHeaders := map[string]string{}
	for k, v := range headers {
		lowerHeaders[strings.ToLower(k)] = toStringAny(v)
	}
	if len(lowerHeaders) != 1 || lowerHeaders["content-type"] != "application/json" {
		t.Errorf("%s: request headers = %v, want {content-type: application/json}", vectorID, lowerHeaders)
	}

	body, _ := input["body"].(map[string]any)
	if body["messageType"] != "initialRequest" {
		t.Errorf("%s: body.messageType = %v, want initialRequest", vectorID, body["messageType"])
	}
	if _, ok := body["version"].(string); !ok {
		t.Errorf("%s: body.version must be a string", vectorID)
	}
	identityKey, _ := body["identityKey"].(string)
	if !pubKeyHexPattern.MatchString(identityKey) {
		t.Errorf("%s: body.identityKey %q does not match pubkey pattern", vectorID, identityKey)
	}

	keys := make([]string, 0, len(body))
	for k := range body {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	wantKeys := []string{"identityKey", "initialNonce", "messageType", "requestedCertificates", "version"}
	if !equalStringSlices(keys, wantKeys) {
		t.Errorf("%s: body keys = %v, want %v", vectorID, keys, wantKeys)
	}

	initialNonce, _ := body["initialNonce"].(string)
	assertBase64Pattern(t, vectorID, "body.initialNonce", initialNonce)
	if decoded, err := base64.StdEncoding.DecodeString(initialNonce); err != nil || len(decoded) != 48 {
		t.Errorf("%s: body.initialNonce must decode to 48 bytes", vectorID)
	}

	rc, _ := body["requestedCertificates"].(map[string]any)
	certifiers, _ := rc["certifiers"].([]any)
	types, _ := rc["types"].(map[string]any)
	if len(rc) != 2 || len(certifiers) != 0 || len(types) != 0 {
		t.Errorf("%s: body.requestedCertificates = %v, want {certifiers: [], types: {}}", vectorID, rc)
	}

	bodyShape, _ := expected["body_shape"].(map[string]any)
	if bodyShape["messageType"] != "initialResponse" {
		t.Errorf("%s: body_shape.messageType = %v, want initialResponse", vectorID, bodyShape["messageType"])
	}
	if bodyShape["version"] != "0.1" {
		t.Errorf("%s: body_shape.version = %v, want 0.1", vectorID, bodyShape["version"])
	}
	for _, key := range []string{"identityKey", "initialNonce", "yourNonce"} {
		if bodyShape[key] != "string" {
			t.Errorf("%s: body_shape.%s = %v, want \"string\"", vectorID, key, bodyShape[key])
		}
	}
	if bodyShape["signature"] != "array" {
		t.Errorf("%s: body_shape.signature = %v, want \"array\"", vectorID, bodyShape["signature"])
	}
}

func dispatchMissingFieldError(t *testing.T, vectorID string, expected map[string]any) {
	t.Helper()
	requireStatus(t, vectorID, expected, 401)
	body, _ := expected["body"].(map[string]any)
	if body["status"] != "error" {
		t.Errorf("%s: body.status = %v, want error", vectorID, body["status"])
	}
	code, _ := body["code"].(string)
	if code != "UNAUTHORIZED" && code != "ERR_AUTH_FAILED" {
		t.Errorf("%s: body.code = %q, want UNAUTHORIZED or ERR_AUTH_FAILED", vectorID, code)
	}
}

func dispatchGeneralRequestHeaders(t *testing.T, vectorID string, expected map[string]any) {
	t.Helper()
	required := toStringSlice(expected["response_headers_required"])
	found := false
	for _, h := range required {
		if strings.ToLower(h) == "x-bsv-auth-signature" {
			found = true
		}
	}
	if !found {
		t.Errorf("%s: response_headers_required = %v, want to contain x-bsv-auth-signature", vectorID, required)
	}
}

func dispatchMissingSignatureError(t *testing.T, vectorID string, expected map[string]any) {
	t.Helper()
	requireStatus(t, vectorID, expected, 401)
	body, _ := expected["body"].(map[string]any)
	if body["status"] != "error" {
		t.Errorf("%s: body.status = %v, want error", vectorID, body["status"])
	}
}

func dispatchBadSignatureError(t *testing.T, vectorID string, expected map[string]any) {
	t.Helper()
	requireStatus(t, vectorID, expected, 401)
	body, _ := expected["body"].(map[string]any)
	if body["status"] != "error" || body["code"] != "ERR_AUTH_FAILED" {
		t.Errorf("%s: body = %v, want {status: error, code: ERR_AUTH_FAILED}", vectorID, body)
	}
}

func dispatchAllowUnauthenticated(t *testing.T, vectorID string, expected map[string]any) {
	t.Helper()
	if expected["req_auth_identity_key"] != "unknown" {
		t.Errorf("%s: req_auth_identity_key = %v, want \"unknown\"", vectorID, expected["req_auth_identity_key"])
	}
}

func dispatchCertificateTimeout(t *testing.T, vectorID string, expected map[string]any) {
	t.Helper()
	requireStatus(t, vectorID, expected, 408)
	body, _ := expected["body"].(map[string]any)
	if body["code"] != "CERTIFICATE_TIMEOUT" {
		t.Errorf("%s: body.code = %v, want CERTIFICATE_TIMEOUT", vectorID, body["code"])
	}
}

func dispatchRequestedCertificatesBody(t *testing.T, vectorID string, expected map[string]any) {
	t.Helper()
	includes, _ := expected["response_body_includes"].(map[string]any)
	if includes["requestedCertificates"] != "present" {
		t.Errorf("%s: response_body_includes.requestedCertificates = %v, want \"present\"", vectorID, includes["requestedCertificates"])
	}
}

func dispatchAuthMessageSchema(t *testing.T, vectorID string, input, expected map[string]any) {
	t.Helper()
	if !getBoolField(input, "_schema_check") {
		t.Errorf("%s: _schema_check must be true", vectorID)
	}
	if input["messageType"] != "initialRequest" {
		t.Errorf("%s: messageType = %v, want initialRequest", vectorID, input["messageType"])
	}
	if _, ok := input["version"].(string); !ok {
		t.Errorf("%s: version must be a string", vectorID)
	}
	identityKey, _ := input["identityKey"].(string)
	if !pubKeyHexPattern.MatchString(identityKey) {
		t.Errorf("%s: identityKey %q does not match pubkey pattern", vectorID, identityKey)
	}
	if nonce, _ := input["initialNonce"].(string); nonce != "" {
		assertBase64Pattern(t, vectorID, "initialNonce", nonce)
	}

	validTypes := toStringSlice(expected["valid_message_types"])
	for _, want := range []string{"initialRequest", "initialResponse", "general"} {
		if !slicesContains(validTypes, want) {
			t.Errorf("%s: valid_message_types = %v, want to contain %q", vectorID, validTypes, want)
		}
	}

	requiredFields := toStringSlice(expected["required_fields"])
	for _, want := range []string{"messageType", "version", "identityKey"} {
		if !slicesContains(requiredFields, want) {
			t.Errorf("%s: required_fields = %v, want to contain %q", vectorID, requiredFields, want)
		}
	}
	for _, field := range requiredFields {
		if input[field] == nil {
			t.Errorf("%s: input[%q] must be defined (required_fields cross-check)", vectorID, field)
		}
	}
}

func dispatchRequestIDFormat(t *testing.T, vectorID string, input, expected map[string]any) {
	t.Helper()
	lengthBytes, _ := toFloat(input["requestId_length_bytes"])
	if lengthBytes != 32 {
		t.Errorf("%s: requestId_length_bytes = %v, want 32", vectorID, lengthBytes)
	}
	expectedLen, _ := toFloat(expected["requestId_base64_length"])
	if expectedLen != 44 {
		t.Errorf("%s: requestId_base64_length = %v, want 44", vectorID, expectedLen)
	}

	example, _ := input["requestId_example"].(string)
	assertBase64Pattern(t, vectorID, "requestId_example", example)
	decoded, err := base64.StdEncoding.DecodeString(example)
	if err != nil || len(decoded) != int(lengthBytes) {
		t.Errorf("%s: requestId_example must decode to %v bytes", vectorID, lengthBytes)
	}
	if len(example) != int(expectedLen) {
		t.Errorf("%s: len(requestId_example) = %d, want %v", vectorID, len(example), expectedLen)
	}
}

func dispatchPubKeyHexFormat(t *testing.T, vectorID string, input, expected map[string]any) {
	t.Helper()
	if !getBoolField(input, "_schema_check") {
		t.Errorf("%s: _schema_check must be true", vectorID)
	}
	pattern, _ := expected["pattern"].(string)
	if pattern != "^0[23][0-9a-fA-F]{64}$" {
		t.Errorf("%s: pattern = %q, want ^0[23][0-9a-fA-F]{64}$", vectorID, pattern)
	}
	for _, ex := range toStringSlice(input["valid_examples"]) {
		if !pubKeyHexPattern.MatchString(ex) {
			t.Errorf("%s: valid example %q does not match pattern", vectorID, ex)
		}
	}
	for _, ex := range toStringSlice(input["invalid_examples"]) {
		if pubKeyHexPattern.MatchString(strings.TrimSpace(ex)) {
			t.Errorf("%s: invalid example %q unexpectedly matches pattern", vectorID, ex)
		}
	}
}

func dispatchReplayPrevention(t *testing.T, vectorID string, expected map[string]any) {
	t.Helper()
	requireStatus(t, vectorID, expected, 401)
	body, _ := expected["body"].(map[string]any)
	if body["code"] != "ERR_AUTH_FAILED" {
		t.Errorf("%s: body.code = %v, want ERR_AUTH_FAILED", vectorID, body["code"])
	}
}

func dispatchResponseSigningFailure(t *testing.T, vectorID string, expected map[string]any) {
	t.Helper()
	requireStatus(t, vectorID, expected, 500)
	body, _ := expected["body"].(map[string]any)
	if body["code"] != "ERR_RESPONSE_SIGNING_FAILED" {
		t.Errorf("%s: body.code = %v, want ERR_RESPONSE_SIGNING_FAILED", vectorID, body["code"])
	}
}

// dispatchResponsePreimage is the one real, bug-catching check in the
// dispatch mirror (auth.brc31-handshake.17-21): it builds a real
// *http.Response with the vector's status/body and feeds it through Go's
// production authpayload.FromHTTPResponse — the same function
// transports.SimplifiedHTTPTransport uses to turn a BRC-104 HTTP response
// into an AuthMessage payload — and checks the resulting preimage bytes
// against the vector's recorded payload_hex. This is where ts-stack#550
// (empty body must encode as -1, not 0) is pinned on the Go side.
func dispatchResponsePreimage(t *testing.T, vectorID string, input, expected map[string]any) {
	t.Helper()

	requestIDHex, _ := input["request_id_hex"].(string)
	bodyHex, _ := input["body_hex"].(string)
	status, _ := toFloat(input["status"])

	requestID, err := hex.DecodeString(requestIDHex)
	if err != nil {
		t.Fatalf("%s: bad request_id_hex: %v", vectorID, err)
	}
	body, err := hex.DecodeString(bodyHex)
	if err != nil {
		t.Fatalf("%s: bad body_hex: %v", vectorID, err)
	}

	header := http.Header{}
	header.Set("x-bsv-auth-version", "0.1")
	header.Set("x-bsv-auth-identity-key", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	header.Set("x-bsv-auth-request-id", base64.StdEncoding.EncodeToString(requestID))
	header.Set("x-bsv-auth-signature", "aabbcc")

	res := &http.Response{
		StatusCode: int(status),
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	payload, err := authpayload.FromHTTPResponse(requestID, res)
	if err != nil {
		t.Fatalf("%s: authpayload.FromHTTPResponse: %v", vectorID, err)
	}
	got := hex.EncodeToString(payload)
	want, _ := expected["payload_hex"].(string)
	if got != want {
		t.Errorf("%s: response preimage = %s, want %s", vectorID, got, want)
	}
}

// ── shared small helpers for this file ──────────────────────────────────────

func toFloat(v any) (float64, bool) {
	f, ok := v.(float64)
	return f, ok
}

func toStringAny(v any) string {
	s, _ := v.(string)
	return s
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func slicesContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func requireStatus(t *testing.T, vectorID string, expected map[string]any, want float64) {
	t.Helper()
	got, ok := toFloat(expected["status"])
	if !ok || got != want {
		t.Errorf("%s: status = %v, want %v", vectorID, expected["status"], want)
	}
}

// ── Part B: real Peer initialRequest emission ───────────────────────────────
//
// TestBRC31HandshakeRealPeerInitialRequestEmission mirrors auth-wire.test.ts:
// it drives a real auth.Peer + a captured Send (standing in for
// SimplifiedFetchTransport's injected fetch) and checks the actual
// JSON-marshaled initialRequest AuthMessage Go emits against the vector's
// recorded fixture. This is the regression test for the bug this domain
// exists to fix: requestedCertificates must marshal as lowercase
// {"certifiers":[],"types":{}}, not {"Certifiers":[],"CertificateTypes":{}}.
func TestBRC31HandshakeRealPeerInitialRequestEmission(t *testing.T) {
	file := conformance.Load(t, "auth/brc31-handshake.json")
	fixture := file.Vectors[0] // auth.brc31-handshake.1
	var in struct {
		Body map[string]any `json:"body"`
	}
	fixture.DecodeInput(t, &in)

	// auth-wire.test.ts drives its Peer from `new PrivateKey(1)` (the
	// fixture's identityKey, 0279be667ef9...798, is that key's pubkey), so
	// this uses the same fixed scalar to reproduce the exact fixture.
	privKey, _ := ec.PrivateKeyFromBytes([]byte{1})
	w := wallet.NewTestWallet(t, privKey)

	sendErr := errors.New("fixture capture complete")
	captured := make(chan *auth.AuthMessage, 1)
	transport := &captureOnceTransport{
		onSend: func(msg *auth.AuthMessage) error {
			captured <- msg
			return sendErr
		},
	}

	peer := auth.NewPeer(&auth.PeerOptions{Wallet: w, Transport: transport})

	counterpartyPriv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	if _, sessErr := peer.GetAuthenticatedSession(t.Context(), counterpartyPriv.PubKey(), 1000); sessErr == nil {
		t.Fatalf("expected GetAuthenticatedSession to fail once the fixture transport aborts the send")
	}

	var msg *auth.AuthMessage
	select {
	case msg = <-captured:
	default:
		t.Fatalf("Peer did not send an initialRequest through the transport")
	}
	if msg.MessageType != auth.MessageTypeInitialRequest {
		t.Fatalf("captured message type = %s, want initialRequest", msg.MessageType)
	}

	raw, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("json.Marshal(AuthMessage): %v", err)
	}
	var body map[string]any
	if unmarshalErr := json.Unmarshal(raw, &body); unmarshalErr != nil {
		t.Fatalf("re-decode marshaled AuthMessage: %v", unmarshalErr)
	}

	assertValidAuthMessageShape(t, "real Peer initialRequest", body)

	keys := make([]string, 0, len(body))
	for k := range body {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	wantKeys := []string{"identityKey", "initialNonce", "messageType", "requestedCertificates", "version"}
	if !equalStringSlices(keys, wantKeys) {
		t.Fatalf("marshaled initialRequest keys = %v, want exactly %v", keys, wantKeys)
	}

	if body["messageType"] != "initialRequest" {
		t.Errorf("messageType = %v, want initialRequest", body["messageType"])
	}
	identityKey, _ := body["identityKey"].(string)
	if !pubKeyHexPattern.MatchString(identityKey) {
		t.Errorf("identityKey %q does not match pubkey pattern", identityKey)
	}
	initialNonce, _ := body["initialNonce"].(string)
	decodedNonce, err := base64.StdEncoding.DecodeString(initialNonce)
	if err != nil || len(decodedNonce) != 48 {
		t.Errorf("initialNonce %q must decode to 48 bytes", initialNonce)
	}

	rc, _ := body["requestedCertificates"].(map[string]any)
	certifiers, _ := rc["certifiers"].([]any)
	types, _ := rc["types"].(map[string]any)
	if len(rc) != 2 || len(certifiers) != 0 || len(types) != 0 {
		t.Errorf("requestedCertificates = %v, want {certifiers: [], types: {}} (this is the RequestedCertificateSet wire-shape bug this domain fixes)", rc)
	}

	// Cross-check against the pinned fixture body, normalizing the
	// (necessarily random) initialNonce first — same comparison
	// auth-wire.test.ts makes against vectors[0].input.body.
	normalized := make(map[string]any, len(body))
	for k, v := range body {
		normalized[k] = v
	}
	normalized["initialNonce"] = in.Body["initialNonce"]
	normalizedJSON, marshalErr := json.Marshal(normalized)
	if marshalErr != nil {
		t.Fatalf("marshal normalized body: %v", marshalErr)
	}
	fixtureJSON, marshalErr := json.Marshal(in.Body)
	if marshalErr != nil {
		t.Fatalf("marshal fixture body: %v", marshalErr)
	}
	if string(normalizedJSON) != string(fixtureJSON) {
		t.Errorf("real Peer initialRequest (nonce-normalized) = %s\nwant (fixture)               = %s", normalizedJSON, fixtureJSON)
	}
}

// captureOnceTransport is a minimal auth.Transport that hands every Send to
// onSend, standing in for auth-wire.test.ts's injected fetch that captures
// the request and then aborts.
type captureOnceTransport struct {
	onSend func(*auth.AuthMessage) error
}

func (c *captureOnceTransport) Send(_ context.Context, message *auth.AuthMessage) error {
	return c.onSend(message)
}

func (c *captureOnceTransport) OnData(func(context.Context, *auth.AuthMessage) error) error {
	return nil
}

func (c *captureOnceTransport) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	return nil, errors.New("captureOnceTransport: no handler registered")
}

// ── Part C: every message type Go emits, validated end to end ──────────────
//
// TestBRC31HandshakeMessageShapesPassTSValidation drives a real, paired
// two-Peer exchange covering all five AuthMessage types (initialRequest,
// initialResponse, certificateResponse via the handshake's own certificate
// exchange, then certificateRequest and general via the explicit APIs), and
// runs the Go port of AuthMessageValidation.ts's shape checks
// (assertValidAuthMessageShape, see validator_test.go) against the exact
// bytes each message marshals to.
func TestBRC31HandshakeMessageShapesPassTSValidation(t *testing.T) {
	alicePriv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	bobPriv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	aliceWallet := wallet.NewTestWallet(t, alicePriv)
	bobWallet := wallet.NewTestWallet(t, bobPriv)

	aliceTransport := &recordingPairedTransport{name: "alice"}
	bobTransport := &recordingPairedTransport{name: "bob"}
	aliceTransport.peer = bobTransport
	bobTransport.peer = aliceTransport

	var mu sync.Mutex
	seenTypes := map[string]bool{}
	record := func(msg *auth.AuthMessage) {
		raw, marshalErr := json.Marshal(msg)
		if marshalErr != nil {
			t.Errorf("marshal %s message: %v", msg.MessageType, marshalErr)
			return
		}
		var body map[string]any
		if unmarshalErr := json.Unmarshal(raw, &body); unmarshalErr != nil {
			t.Errorf("re-decode marshaled %s message: %v", msg.MessageType, unmarshalErr)
			return
		}
		assertValidAuthMessageShape(t, string(msg.MessageType), body)
		mu.Lock()
		seenTypes[string(msg.MessageType)] = true
		mu.Unlock()
	}
	aliceTransport.onMessage = record
	bobTransport.onMessage = record

	certType, err := wallet.CertificateTypeFromString("contact")
	if err != nil {
		t.Fatalf("CertificateTypeFromString: %v", err)
	}

	// Alice has a matching certificate ready (issued by the test suite's
	// default certifier, like the existing auth package tests), so the
	// handshake completes with Bob's certificate request satisfied
	// automatically (Peer.sendCertificates -> SendCertificateResponse).
	aliceCertManager := testcertificates.NewManager(t, aliceWallet)
	aliceCert := aliceCertManager.CertificateForTest().WithType("contact").
		WithFieldValue("name", "Alice").
		Issue()

	bob := auth.NewPeer(&auth.PeerOptions{
		Wallet:    bobWallet,
		Transport: bobTransport,
		CertificatesToRequest: &utils.RequestedCertificateSet{
			Certifiers:       []*ec.PublicKey{aliceCert.WalletCert.Certifier},
			CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{certType: []string{"name"}},
		},
	})
	alice := auth.NewPeer(&auth.PeerOptions{Wallet: aliceWallet, Transport: aliceTransport})

	received := make(chan struct{}, 1)
	bob.ListenForGeneralMessages(func(context.Context, *ec.PublicKey, []byte) error {
		received <- struct{}{}
		return nil
	})

	if err := alice.ToPeer(t.Context(), []byte("hello"), bobPriv.PubKey(), 5000); err != nil {
		t.Fatalf("alice.ToPeer: %v", err)
	}
	select {
	case <-received:
	default:
		t.Fatalf("Bob never received Alice's general message")
	}

	// A standalone RequestCertificates call exercises certificateRequest
	// (and another certificateResponse) on an already-authenticated session.
	if err := alice.RequestCertificates(t.Context(), bobPriv.PubKey(), utils.RequestedCertificateSet{
		Certifiers:       []*ec.PublicKey{bobPriv.PubKey()},
		CertificateTypes: utils.RequestedCertificateTypeIDAndFieldList{certType: []string{"name"}},
	}, 5000); err != nil {
		t.Fatalf("alice.RequestCertificates: %v", err)
	}

	for _, want := range []string{"initialRequest", "initialResponse", "certificateResponse", "certificateRequest", "general"} {
		if !seenTypes[want] {
			t.Errorf("never observed a %q message in this exchange (coverage gap)", want)
		}
	}
}

// recordingPairedTransport is a minimal, directly-paired auth.Transport
// (like auth_test's own MockTransport in /auth/peer_test.go, which this
// package cannot import) that calls onMessage with every AuthMessage passed
// to Send before delivering it synchronously to the paired peer's handler.
type recordingPairedTransport struct {
	name      string
	peer      *recordingPairedTransport
	handler   func(context.Context, *auth.AuthMessage) error
	onMessage func(*auth.AuthMessage)
}

func (rt *recordingPairedTransport) Send(ctx context.Context, message *auth.AuthMessage) error {
	if rt.onMessage != nil {
		rt.onMessage(message)
	}
	if rt.peer == nil || rt.peer.handler == nil {
		return errors.New(rt.name + ": paired transport has no handler registered")
	}
	return rt.peer.handler(ctx, message)
}

func (rt *recordingPairedTransport) OnData(callback func(context.Context, *auth.AuthMessage) error) error {
	rt.handler = callback
	return nil
}

func (rt *recordingPairedTransport) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	if rt.handler == nil {
		return nil, errors.New(rt.name + ": no handler registered")
	}
	return rt.handler, nil
}
