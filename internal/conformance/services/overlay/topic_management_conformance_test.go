package overlay_test

import (
	"encoding/json"
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
)

// TestOverlayTopicManagement covers the overlay-node admin/health/arc-ingest
// HTTP surface. Neither the Go SDK nor the TS @bsv/sdk ship a client for
// these node-operator routes (overlay-express is the only implementation),
// so - exactly like conformance/runner/ts/dispatchers/overlay.ts's
// dispatchTopicManagement - this validates the vector's own request/response
// shapes structurally rather than driving a live client.
func TestOverlayTopicManagement(t *testing.T) {
	f := conformance.Load(t, "overlay/topic-management.json")
	conformance.Run(t, f, func(t *testing.T, v conformance.Vector) {
		in := decodeInput(t, v)
		exp := decodeExpected(t, v)
		assertHTTPStatusShape(t, exp)

		status := 200
		if s := expectedStatuses(exp); len(s) > 0 {
			status = s[0]
		}

		switch in.Path {
		case "/health", "/health/live", "/health/ready":
			assertHealthReportShape(t, exp, status)
		case "/admin/config":
			if status != 200 {
				t.Errorf("/admin/config expected 200, got %d", status)
			}
			if key, ok := exp.Body["adminIdentityKey"]; ok {
				if key != nil {
					if _, ok := key.(string); !ok {
						t.Errorf("adminIdentityKey is neither string nor null: %#v", key)
					}
				}
			}
			if name, ok := exp.Body["nodeName"]; ok {
				if _, ok := name.(string); !ok {
					t.Errorf("nodeName is not a string: %#v", name)
				}
			}
		case "/admin/stats":
			if status == 200 {
				assertSuccessEnvelope(t, exp.Body)
			} else {
				assertErrorShape(t, exp.Body)
			}
		case "/admin/ban", "/admin/unban":
			var reqBody map[string]any
			_ = decodeVectorBody(v, &reqBody)
			assertBanRequestShape(t, reqBody)
			if status == 200 {
				if exp.Body["status"] != "success" {
					t.Errorf("ban/unban success body.status = %v, want success", exp.Body["status"])
				}
			} else {
				assertErrorShape(t, exp.Body)
			}
		case "/admin/bans":
			if status == 200 {
				assertSuccessEnvelope(t, exp.Body)
				if data, ok := exp.Body["data"].(map[string]any); ok {
					if bans, ok := data["bans"].([]any); ok {
						for _, raw := range bans {
							b, ok := raw.(map[string]any)
							if !ok {
								t.Fatalf("ban record is not an object: %#v", raw)
							}
							if typ, ok := b["type"]; ok && typ != "domain" && typ != "outpoint" {
								t.Errorf("ban record type = %v, want domain or outpoint", typ)
							}
						}
					}
				}
			} else {
				assertErrorShape(t, exp.Body)
			}
		case "/admin/evictOutpoint":
			var reqBody map[string]any
			_ = decodeVectorBody(v, &reqBody)
			if txid, ok := reqBody["txid"]; ok {
				s, ok := txid.(string)
				if !ok || len(s) != 64 {
					t.Errorf("evictOutpoint txid = %#v, want 64-char hex string", txid)
				}
			}
			if status == 200 {
				if exp.Body["status"] != "success" {
					t.Errorf("evictOutpoint success body.status = %v, want success", exp.Body["status"])
				}
			} else {
				assertErrorShape(t, exp.Body)
			}
		case "/admin/ship-records":
			if status == 200 {
				assertSuccessEnvelope(t, exp.Body)
				if data, ok := exp.Body["data"].(map[string]any); ok {
					requireNonNegNumber(t, data, "total")
					requireNonNegNumber(t, data, "page")
					requireNonNegNumber(t, data, "limit")
					requireNonNegNumber(t, data, "pages")
				}
			} else {
				assertErrorShape(t, exp.Body)
			}
		case "/arc-ingest":
			var reqBody map[string]any
			_ = decodeVectorBody(v, &reqBody)
			if txid, ok := reqBody["txid"]; ok {
				s, ok := txid.(string)
				if !ok || len(s) != 64 {
					t.Errorf("arc-ingest txid = %#v, want 64-char hex string", txid)
				}
			}
			if status == 200 {
				if exp.Body["status"] != "success" {
					t.Errorf("arc-ingest success body.status = %v, want success", exp.Body["status"])
				}
			} else {
				assertErrorShape(t, exp.Body)
			}
		default:
			// Nothing further documented for this path; the status-shape
			// check above already ran.
		}
	})
}

func decodeVectorBody(v conformance.Vector, dst *map[string]any) error {
	var wrapper struct {
		Body json.RawMessage `json:"body"`
	}
	if err := json.Unmarshal(v.Input, &wrapper); err != nil {
		return err
	}
	if len(wrapper.Body) == 0 {
		return nil
	}
	return json.Unmarshal(wrapper.Body, dst)
}

func assertHealthReportShape(t *testing.T, exp vectorExpected, status int) {
	t.Helper()
	body := exp.Body
	if live, ok := body["live"]; ok {
		if _, ok := live.(bool); !ok {
			t.Errorf("health.live is not a bool: %#v", live)
		}
	}
	if ready, ok := body["ready"]; ok {
		if _, ok := ready.(bool); !ok {
			t.Errorf("health.ready is not a bool: %#v", ready)
		}
	}
	allowedStatus := map[string]bool{"ok": true, "degraded": true, "error": true}
	if s, ok := body["status"]; ok {
		if str, ok := s.(string); !ok || !allowedStatus[str] {
			t.Errorf("health.status = %#v, want one of ok/degraded/error", s)
		}
	}
	if oneof, ok := body["status_oneof"].([]any); ok {
		for _, s := range oneof {
			if str, ok := s.(string); !ok || !allowedStatus[str] {
				t.Errorf("health.status_oneof entry = %#v, want one of ok/degraded/error", s)
			}
		}
	}
	if status == 503 {
		if ready, ok := body["ready"]; ok && ready != false {
			t.Errorf("503 health response has ready = %v, want false", ready)
		}
	}
}

func assertSuccessEnvelope(t *testing.T, body map[string]any) {
	t.Helper()
	if body["status"] != "success" {
		t.Errorf("success body.status = %v, want success", body["status"])
	}
}

func assertBanRequestShape(t *testing.T, body map[string]any) {
	t.Helper()
	if typ, ok := body["type"]; ok && typ != "domain" && typ != "outpoint" {
		t.Errorf("ban request type = %v, want domain or outpoint", typ)
	}
	if val, ok := body["value"]; ok {
		if _, ok := val.(string); !ok {
			t.Errorf("ban request value is not a string: %#v", val)
		}
	}
}

func requireNonNegNumber(t *testing.T, data map[string]any, key string) {
	t.Helper()
	raw, ok := data[key]
	if !ok {
		return
	}
	n, ok := raw.(float64)
	if !ok || n < 0 {
		t.Errorf("%s = %#v, want a non-negative number", key, raw)
	}
}
