// Package broadcast_test runs the ts-stack conformance vectors for
// broadcast/{arc-submit,merkle-path-validation,merkle-service}.json.
//
// Unlike the TS reference runner (conformance/runner/ts/dispatchers/broadcast.ts
// and broadcastHelpers.ts in ts-stack), which drives @bsv/sdk's ARC class
// through a synthetic in-process fetch mock, these tests spin up a real
// httptest.Server so we can additionally verify the wire shape go-sdk's Arc
// client actually emits (method, path, Content-Type, JSON field names) and
// not just how it parses a canned response.
//
// merkle-service vectors, and the ARC-callback ("/arc-ingest") validation
// vectors in merkle-path-validation.json, exercise no go-sdk production code
// at all: they are pure schema/business-rule checks against a hypothetical
// merkle-service and ARC-callback-ingest HTTP contract that ts-stack's own
// dispatcher implements as freestanding TS (validateArcCallbackPayload,
// simulateWatchRequest, assertSchemaCheckVector — none of it is @bsv/sdk
// exported code either), so we port that same logic here rather than
// invoking anything in transaction/broadcaster.
package broadcast_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/broadcaster"
)

// jsonMap is how every vector's heterogeneous input/expected object is
// decoded: field shapes differ enough per vector (and even per key — e.g.
// merkle-service.13's expected.status is the string "ok" while
// arc-submit.*'s expected.status is an HTTP status number) that a single
// fixed Go struct can't decode the whole file.
type jsonMap = map[string]any

func getString(m jsonMap, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func getBool(m jsonMap, key string) bool {
	if m == nil {
		return false
	}
	b, _ := m[key].(bool)
	return b
}

func getFloat(m jsonMap, key string) (float64, bool) {
	if m == nil {
		return 0, false
	}
	f, ok := m[key].(float64)
	return f, ok
}

func getMap(m jsonMap, key string) jsonMap {
	if m == nil {
		return nil
	}
	sub, _ := m[key].(jsonMap)
	return sub
}

func getStringSlice(m jsonMap, key string) []string {
	raw, ok := m[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		if s, ok := r.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ── shared httptest plumbing ─────────────────────────────────────────────────

// capturedRequest records the shape of the single request an httptest server
// received, so tests can assert go-sdk actually emitted it (not just that it
// handles a canned response correctly).
type capturedRequest struct {
	Method      string
	Path        string
	ContentType string
	Body        jsonMap
}

// serveJSON starts an httptest.Server that always answers with the given
// status and JSON body, recording the request it received into capture.
func serveJSON(t *testing.T, status int, body []byte, capture *capturedRequest) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.Method = r.Method
		capture.Path = r.URL.Path
		capture.ContentType = r.Header.Get("Content-Type")
		if raw, err := io.ReadAll(r.Body); err == nil && len(raw) > 0 {
			var m jsonMap
			if json.Unmarshal(raw, &m) == nil {
				capture.Body = m
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return server
}

// buildTestTx returns a minimal, valid, zero-input transaction. Its content
// is irrelevant to every arc-submit vector: the httptest server always
// answers with the vector's canned response regardless of what was posted,
// exactly as ts-stack's synthetic fetch mock does. Zero inputs keeps
// rawTxHex's EF-vs-raw-hex decision trivial (EF of an input-less tx never
// needs a source output).
func buildTestTx(t *testing.T) *transaction.Transaction {
	t.Helper()
	tx := transaction.NewTransaction()
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1000,
		LockingScript: &script.Script{},
	})
	return tx
}

// ── broadcast/arc-submit.json ────────────────────────────────────────────────

func TestArcSubmitConformance(t *testing.T) {
	file := conformance.Load(t, "broadcast/arc-submit.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in jsonMap
		v.DecodeInput(t, &in)
		var exp jsonMap
		v.DecodeExpected(t, &exp)

		switch v.ID {
		// Happy-path single-tx submissions: HTTP 200, a non-failure txStatus.
		case "broadcast.arcsubmit.1", "broadcast.arcsubmit.2", "broadcast.arcsubmit.3",
			"broadcast.arcsubmit.8", "broadcast.arcsubmit.11":
			expBody := getMap(exp, "body")
			captured, success, failure, submittedTxid := postArcTx(t, exp, expBody)
			require.Equal(t, "POST", captured.Method)
			require.Equal(t, "/v1/tx", captured.Path)
			require.Contains(t, strings.ToLower(captured.ContentType), "application/json")
			require.Contains(t, captured.Body, "rawTx", "go-sdk's ARC client must POST a JSON {rawTx} body")
			require.Nil(t, failure)
			require.NotNil(t, success)
			require.True(t, txidPattern.MatchString(getString(expBody, "txid")))
			require.Equal(t, submittedTxid, success.Txid)

		// HTTP-200-but-failure txStatus values.
		case "broadcast.arcsubmit.4": // DOUBLE_SPEND_ATTEMPTED
			expBody := getMap(exp, "body")
			_, success, failure, _ := postArcTx(t, exp, expBody)
			require.Nil(t, success)
			require.NotNil(t, failure)
			require.Equal(t, "DOUBLE_SPEND_ATTEMPTED", failure.Code)
			require.Equal(t, getStringSlice(expBody, "competingTxs"), failure.CompetingTxs)
			require.Equal(t, expectedArcFailureDescription(expBody), failure.Description)

		case "broadcast.arcsubmit.5": // REJECTED
			expBody := getMap(exp, "body")
			_, success, failure, _ := postArcTx(t, exp, expBody)
			require.Nil(t, success)
			require.NotNil(t, failure)
			require.Equal(t, "REJECTED", failure.Code)
			require.Equal(t, expectedArcFailureDescription(expBody), failure.Description)

		// Non-200 HTTP responses.
		case "broadcast.arcsubmit.6": // 422, detail present
			expBody := getMap(exp, "body")
			_, success, failure, _ := postArcTx(t, exp, expBody)
			require.Nil(t, success)
			require.NotNil(t, failure)
			require.Equal(t, "422", failure.Code)
			require.Equal(t, getString(expBody, "detail"), failure.Description)

		case "broadcast.arcsubmit.7": // 401, no detail field
			expBody := getMap(exp, "body")
			_, success, failure, _ := postArcTx(t, exp, expBody)
			require.Nil(t, success)
			require.NotNil(t, failure)
			require.Equal(t, "401", failure.Code)
			// ts-sdk's failedArcResponse defaults to "Unknown error" when no
			// "detail" field is present; it never reads the response's "title".
			require.Equal(t, "Unknown error", failure.Description)

		case "broadcast.arcsubmit.16": // 429, no detail field
			expBody := getMap(exp, "body")
			_, success, failure, _ := postArcTx(t, exp, expBody)
			require.Nil(t, success)
			require.NotNil(t, failure)
			require.Equal(t, "429", failure.Code)
			require.Equal(t, "Unknown error", failure.Description)

		case "broadcast.arcsubmit.9", "broadcast.arcsubmit.10":
			conformance.GoGap(t, "go-sdk's Arc broadcaster has no batch POST /v1/txs "+
				"method (ts-sdk ARC.broadcastMany); transaction/broadcaster/arc.go only submits one tx at a time")

		case "broadcast.arcsubmit.12": // GET /v1/tx/<txid>, 200
			body, err := json.Marshal(getMap(exp, "body"))
			require.NoError(t, err)
			txid := strings.TrimPrefix(getString(in, "path"), "/v1/tx/")
			var captured capturedRequest
			server := serveJSON(t, 200, body, &captured)
			arc := &broadcaster.Arc{ApiUrl: server.URL + "/v1"}
			resp, err := arc.Status(txid)
			require.NoError(t, err)
			require.Equal(t, "GET", captured.Method)
			require.Equal(t, "/v1/tx/"+txid, captured.Path)
			require.Equal(t, getString(getMap(exp, "body"), "txid"), resp.Txid)
			require.NotNil(t, resp.TxStatus)
			require.Equal(t, getString(getMap(exp, "body"), "txStatus"), string(*resp.TxStatus))

		case "broadcast.arcsubmit.13": // GET /v1/tx/<txid>, 404
			expBody := getMap(exp, "body")
			body, err := json.Marshal(expBody)
			require.NoError(t, err)
			txid := strings.TrimPrefix(getString(in, "path"), "/v1/tx/")
			var captured capturedRequest
			server := serveJSON(t, 404, body, &captured)
			arc := &broadcaster.Arc{ApiUrl: server.URL + "/v1"}
			resp, err := arc.Status(txid)
			require.NoError(t, err) // Status() reports transport/decode errors only, not HTTP status
			require.Equal(t, "/v1/tx/"+txid, captured.Path)
			statusWant, _ := getFloat(expBody, "status")
			require.Equal(t, int(statusWant), resp.Status)
			require.Equal(t, getString(expBody, "title"), resp.Title)

		case "broadcast.arcsubmit.14": // arc-ingest callback: schema-only, no client to drive
			expBody := getMap(exp, "body")
			require.Equal(t, "success", getString(expBody, "status"))

		case "broadcast.arcsubmit.15": // schema-only: status_oneof must be all numbers
			for _, s := range exp["status_oneof"].([]any) {
				_, isNumber := s.(float64)
				require.True(t, isNumber)
			}

		default:
			t.Fatalf("unhandled vector id %q", v.ID)
		}
	})
}

// expectedArcFailureDescription mirrors ts-sdk's successfulArcResponse
// description for an HTTP-200-but-failure-txStatus response:
// `${txStatus} ${extraInfo ?? ”}`.trim().
func expectedArcFailureDescription(expBody jsonMap) string {
	return strings.TrimSpace(getString(expBody, "txStatus") + " " + getString(expBody, "extraInfo"))
}

// postArcTx drives broadcaster.Arc.BroadcastCtx through an httptest server
// answering with the vector's expected HTTP status and body, and returns the
// captured request alongside the SDK's parsed result.
//
// ts-stack drives ARC with a synthetic transaction whose id() returns the
// vector's txid, so ARC's echoed txid matches the submitted one. A real Go
// transaction cannot take an arbitrary txid, so the equivalent here is the
// reverse: the canned response echoes the submitted transaction's txid in
// place of the vector's. The returned submittedTxid is what the vector's txid
// stands for.
func postArcTx(t *testing.T, exp, expBody jsonMap) (captured capturedRequest, success *transaction.BroadcastSuccess, failure *transaction.BroadcastFailure, submittedTxid string) {
	t.Helper()
	status, _ := getFloat(exp, "status")
	tx := buildTestTx(t)
	submittedTxid = tx.TxID().String()

	response := make(jsonMap, len(expBody))
	for k, val := range expBody {
		response[k] = val
	}
	if txidPattern.MatchString(getString(expBody, "txid")) {
		response["txid"] = submittedTxid
	}
	body, err := json.Marshal(response)
	require.NoError(t, err)

	server := serveJSON(t, int(status), body, &captured)
	arc := &broadcaster.Arc{ApiUrl: server.URL + "/v1", ApiKey: "test-api-key-abc123"}
	success, failure = arc.BroadcastCtx(context.Background(), tx)
	return captured, success, failure, submittedTxid
}

// ── broadcast/merkle-path-validation.json ────────────────────────────────────

var (
	txidPattern       = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	merklePathCharset = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// validateArcCallbackPayload ports ts-stack's validateArcCallbackPayload
// (conformance/runner/ts/dispatchers/broadcastHelpers.ts): it is a
// freestanding validator for a hypothetical ARC-callback-ingest HTTP
// contract, not go-sdk (or @bsv/sdk) production code, so it is reimplemented
// here rather than called.
func validateArcCallbackPayload(body jsonMap) bool {
	txid, hasTxid := body["txid"]
	txidStr, txidIsString := txid.(string)
	if !hasTxid || !txidIsString || !txidPattern.MatchString(txidStr) {
		return false
	}

	blockHeight, hasBlockHeight := getFloat(body, "blockHeight")
	if !hasBlockHeight || blockHeight != float64(int64(blockHeight)) || blockHeight < 0 {
		return false
	}

	merklePath, hasMerklePath := body["merklePath"]
	merklePathStr, merklePathIsString := merklePath.(string)
	if !hasMerklePath || !merklePathIsString || !merklePathCharset.MatchString(merklePathStr) {
		return false
	}
	// Even-length check, exempting genesis (blockHeight 0) — see
	// broadcast.merklepath.6 in the vector file.
	if blockHeight != 0 && len(merklePathStr)%2 != 0 {
		return false
	}
	return true
}

func TestMerklePathValidationConformance(t *testing.T) {
	file := conformance.Load(t, "broadcast/merkle-path-validation.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in jsonMap
		v.DecodeInput(t, &in)
		var exp jsonMap
		v.DecodeExpected(t, &exp)

		if getString(in, "method") == "POST" && getString(in, "path") == "/v1/tx" {
			// broadcast.merklepath.10/11: ARC answers HTTP 200 with an
			// txStatus ts-sdk treats as failure (SEEN_IN_ORPHAN_MEMPOOL /
			// MINED_IN_STALE_BLOCK).
			expBody := getMap(exp, "body")
			_, success, failure, _ := postArcTx(t, exp, expBody)
			require.Nil(t, success)
			require.NotNil(t, failure)
			require.Equal(t, getString(expBody, "txStatus"), failure.Code)
			require.Equal(t, expectedArcFailureDescription(expBody), failure.Description)
			require.Equal(t, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", getString(expBody, "txid"))
			return
		}

		// broadcast.merklepath.1-9: ARC-callback ("/arc-ingest") payload
		// validation.
		body := getMap(in, "body")
		valid := validateArcCallbackPayload(body)
		wantStatus, _ := getFloat(exp, "status")
		expBody := getMap(exp, "body")

		switch int(wantStatus) {
		case 200:
			require.True(t, valid)
			merklePath := getString(body, "merklePath")
			blockHeight, _ := getFloat(body, "blockHeight")
			if len(merklePath)%2 == 0 {
				// Only even-length hex is worth handing to the BUMP parser —
				// same guard ts-stack's assertMerklePathParseable applies
				// before calling MerklePath.fromHex.
				if mp, err := transaction.NewMerklePathFromHex(merklePath); err == nil {
					require.Equal(t, uint32(blockHeight), mp.BlockHeight)
				}
			}
			require.Equal(t, "success", getString(expBody, "status"))
		case 400:
			require.False(t, valid)
			require.Equal(t, "error", getString(expBody, "status"))
		default:
			t.Fatalf("vector %q: unexpected expected.status %v", v.ID, wantStatus)
		}
	})
}

// ── broadcast/merkle-service.json ────────────────────────────────────────────

func isValidHTTPURL(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// simulatedWatchResult mirrors ts-stack's SimulatedWatchResult.
type simulatedWatchResult struct {
	status int
	errMsg string
}

// simulateWatchRequest ports ts-stack's simulateWatchRequest
// (conformance/runner/ts/dispatchers/broadcastHelpers.ts): a hand-simulated
// merkle-service /watch handler that exists only in the conformance harness
// on both sides (no @bsv/sdk or go-sdk code implements a merkle service), so
// it is reimplemented here rather than called.
func simulateWatchRequest(in, body jsonMap) simulatedWatchResult {
	if _, hasBodyRaw := in["body_raw"]; hasBodyRaw {
		return simulatedWatchResult{status: 400, errMsg: "invalid request body"}
	}
	txid, hasTxid := body["txid"]
	if !hasTxid || txid == nil {
		return simulatedWatchResult{status: 400, errMsg: "txid is required"}
	}
	txidStr, ok := txid.(string)
	if !ok || !txidPattern.MatchString(txidStr) {
		return simulatedWatchResult{status: 400, errMsg: "invalid txid format: must be a 64-character hex string"}
	}
	callbackURL, hasCallback := body["callbackUrl"]
	if !hasCallback || callbackURL == nil {
		return simulatedWatchResult{status: 400, errMsg: "callbackUrl is required"}
	}
	if !isValidHTTPURL(callbackURL) {
		return simulatedWatchResult{status: 400, errMsg: "invalid callbackUrl: must be a valid HTTP/HTTPS URL"}
	}
	if getString(in, "_scenario") == "Aerospike write fails with internal error" {
		return simulatedWatchResult{status: 500, errMsg: "internal server error"}
	}
	return simulatedWatchResult{status: 200}
}

func TestMerkleServiceConformance(t *testing.T) {
	file := conformance.Load(t, "broadcast/merkle-service.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		var in jsonMap
		v.DecodeInput(t, &in)
		var exp jsonMap
		v.DecodeExpected(t, &exp)

		if getBool(in, "_schema_check") {
			assertSchemaCheckVector(t, v.ID, in, exp)
			return
		}

		wantStatus, _ := getFloat(exp, "status")
		expBody := getMap(exp, "body")

		switch {
		case getString(in, "method") == "POST" && getString(in, "path") == "/watch":
			sim := simulateWatchRequest(in, getMap(in, "body"))
			require.Equal(t, int(wantStatus), sim.status)
			if sim.status == 200 {
				require.Equal(t, "ok", getString(expBody, "status"))
			} else {
				gotErr := getString(expBody, "error")
				require.NotEmpty(t, gotErr)
				require.Equal(t, sim.errMsg, gotErr)
			}

		case getString(in, "method") == "GET" && getString(in, "path") == "/health":
			switch int(wantStatus) {
			case 200:
				require.Equal(t, "healthy", getString(expBody, "status"))
				require.Equal(t, "connected", getString(getMap(expBody, "details"), "aerospike"))
			case 503:
				require.Equal(t, "unhealthy", getString(expBody, "status"))
				require.NotEmpty(t, getString(getMap(expBody, "details"), "aerospike"))
			default:
				t.Fatalf("vector %q: unexpected health status %v", v.ID, wantStatus)
			}

		default:
			t.Fatalf("unhandled vector id %q", v.ID)
		}
	})
}

// assertSchemaCheckVector ports ts-stack's assertSchemaCheckVector.
func assertSchemaCheckVector(t *testing.T, id string, in, exp jsonMap) {
	t.Helper()

	if pattern := getString(exp, "pattern"); pattern != "" {
		re := regexp.MustCompile(pattern)
		for _, txid := range getStringSlice(in, "valid_txids") {
			require.Truef(t, re.MatchString(txid), "%q should match %s", txid, pattern)
		}
		for _, txid := range getStringSlice(in, "invalid_txids") {
			require.Falsef(t, re.MatchString(txid), "%q should not match %s", txid, pattern)
		}
		return
	}

	// broadcast.merkle-service.13: WatchResponse schema — "message" must be a
	// string when status is "ok".
	if getString(exp, "status") == "ok" {
		_, isString := exp["message"].(string)
		require.Truef(t, isString, "vector %q: expected.message must be a string", id)
		return
	}

	t.Fatalf("vector %q: unrecognized schema-check shape", id)
}
