package auth_test

import (
	"regexp"
	"slices"
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
)

// TestAuthSocketConformance mirrors, one for one, the routing and assertions
// of conformance/runner/ts/dispatchers/messaging.ts's dispatchAuthSocket for
// category "authsocket". Every vector in messaging/authsocket.json documents
// the AsyncAPI / BRC-103-over-WebSocket protocol shape rather than exercising
// a live socket server (the TS reference dispatcher does the same — no
// WebSocket server is spun up there either), so these are structural
// assertions against the vector's own recorded input/expected shapes.
func TestAuthSocketConformance(t *testing.T) {
	file := conformance.Load(t, "messaging/authsocket.json")
	conformance.Run(t, file, func(t *testing.T, v conformance.Vector) {
		input := decodeGenericObject(t, v.ID, v.Input)
		expected := decodeGenericObject(t, v.ID, v.Expected)
		dispatchAuthSocket(t, v.ID, input, expected)
	})
}

func dispatchAuthSocket(t *testing.T, vectorID string, input, expected map[string]any) {
	t.Helper()

	if getBoolField(input, "_schema_check") {
		dispatchAuthSocketSchema(t, vectorID, input, expected)
		return
	}

	socketEvent, hasSocketEvent := input["socketio_event"]

	if socketEvent == "authMessage" && dispatchAuthMessageEvent(t, vectorID, input, expected) {
		return
	}

	if socketEvent == "message" {
		dispatchMessageEvent(t, vectorID, input, expected)
		return
	}

	if !hasSocketEvent || socketEvent == nil {
		if _, ok := expected["server_disconnects"]; ok {
			assertBoolFieldTrue(t, vectorID, "server_disconnects", expected)
		}
		return
	}

	if _, ok := input["expected_identity_key"]; ok {
		dispatchKnownIdentity(t, vectorID, input, expected)
	}
}

func dispatchAuthSocketSchema(t *testing.T, vectorID string, input, expected map[string]any) {
	t.Helper()

	if envelope, ok := input["envelope"].(map[string]any); ok {
		dispatchEnvelopeSchema(t, vectorID, envelope, expected)
		return
	}
	if _, ok := input["valid_types"]; ok {
		dispatchMessageTypeSchema(t, vectorID, input, expected)
		return
	}
	if _, ok := expected["production_url"]; ok {
		if _, ok := expected["production_url"].(string); !ok {
			t.Errorf("%s: production_url must be a string", vectorID)
		}
		assertStringFieldEquals(t, vectorID, "protocol", expected, "wss")
		assertStringFieldEquals(t, vectorID, "transport", expected, "Socket.IO")
		return
	}
	if _, ok := expected["transport_handles"]; ok {
		appSees, ok := expected["application_sees"].(map[string]any)
		if !ok {
			t.Fatalf("%s: application_sees must be an object", vectorID)
		}
		if _, ok := appSees["eventName"]; !ok {
			t.Errorf("%s: application_sees missing eventName", vectorID)
		}
		if _, ok := appSees["data"]; !ok {
			t.Errorf("%s: application_sees missing data", vectorID)
		}
		return
	}
	if _, ok := input["required_fields"]; ok {
		dispatchRequiredFieldSchema(t, vectorID, input, expected)
		return
	}
	if _, ok := input["valid_examples"]; ok {
		dispatchPublicKeySchema(t, vectorID, input, expected)
	}
}

func dispatchEnvelopeSchema(t *testing.T, vectorID string, envelope, expected map[string]any) {
	t.Helper()
	fields, _ := expected["required_fields"].([]any)
	for _, f := range fields {
		name, ok := f.(string)
		if !ok {
			continue
		}
		if _, ok := envelope[name]; !ok {
			t.Errorf("%s: envelope missing required field %q", vectorID, name)
		}
	}
	if v, ok := expected["valid"]; ok {
		assertBoolFieldTrue(t, vectorID, "valid", map[string]any{"valid": v})
	}
}

func dispatchMessageTypeSchema(t *testing.T, vectorID string, input, expected map[string]any) {
	t.Helper()
	validTypes := toStringSlice(input["valid_types"])
	expectedEnum := toStringSlice(expected["enum"])
	if validTypes == nil || expectedEnum == nil {
		return
	}
	sortedA := append([]string(nil), validTypes...)
	sortedB := append([]string(nil), expectedEnum...)
	slices.Sort(sortedA)
	slices.Sort(sortedB)
	if !slices.Equal(sortedA, sortedB) {
		t.Errorf("%s: valid_types %v != expected enum %v", vectorID, validTypes, expectedEnum)
	}
}

func dispatchRequiredFieldSchema(t *testing.T, vectorID string, input, expected map[string]any) {
	t.Helper()
	fields := toStringSlice(input["required_fields"])
	if len(fields) == 0 {
		t.Errorf("%s: required_fields must be non-empty", vectorID)
	}
	if v, ok := expected["valid"]; ok {
		assertBoolFieldTrue(t, vectorID, "valid", map[string]any{"valid": v})
	}
}

func dispatchPublicKeySchema(t *testing.T, vectorID string, input, expected map[string]any) {
	t.Helper()
	pattern, _ := expected["pattern"].(string)
	validExamples := toStringSlice(input["valid_examples"])
	if pattern == "" || validExamples == nil {
		return
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("%s: bad pattern %q: %v", vectorID, pattern, err)
	}
	for _, example := range validExamples {
		if !re.MatchString(example) {
			t.Errorf("%s: example %q does not match pattern %q", vectorID, example, pattern)
		}
	}
}

func dispatchAuthMessageEvent(t *testing.T, vectorID string, input, expected map[string]any) bool {
	t.Helper()
	payload, _ := input["payload"].(map[string]any)
	messageType, _ := payload["messageType"].(string)

	switch messageType {
	case "initialRequest":
		dispatchInitialRequestShape(t, vectorID, expected)
		return true
	case "general":
		if payload != nil {
			dispatchGeneralAuthMessage(t, vectorID, expected)
			return true
		}
	}
	return false
}

func dispatchInitialRequestShape(t *testing.T, vectorID string, expected map[string]any) {
	t.Helper()
	if responseShape, ok := expected["response_shape"].(map[string]any); ok {
		if responseShape["messageType"] != "initialResponse" {
			t.Errorf("%s: response_shape.messageType = %v, want initialResponse", vectorID, responseShape["messageType"])
		}
		for _, key := range []string{"identityKey", "initialNonce", "signature"} {
			if _, ok := responseShape[key]; !ok {
				t.Errorf("%s: response_shape missing %q", vectorID, key)
			}
		}
	}
	if v, ok := expected["response_shape_includes"]; ok && v == nil {
		t.Errorf("%s: response_shape_includes must be defined", vectorID)
	}
}

func dispatchGeneralAuthMessage(t *testing.T, vectorID string, expected map[string]any) {
	t.Helper()
	if _, ok := expected["server_processes"]; ok {
		assertBoolFieldTrue(t, vectorID, "server_processes", expected)
	}
	if _, ok := expected["inner_event_extracted_from_payload"]; ok {
		assertBoolFieldTrue(t, vectorID, "inner_event_extracted_from_payload", expected)
	}
}

func dispatchMessageEvent(t *testing.T, vectorID string, input, expected map[string]any) {
	t.Helper()
	if payload, ok := input["payload_example"].(map[string]any); ok {
		fields := toStringSlice(expected["payload_has_fields"])
		for _, f := range fields {
			if _, ok := payload[f]; !ok {
				t.Errorf("%s: payload_example missing field %q", vectorID, f)
			}
		}
	}
	if s, ok := expected["event_received"].(string); ok && s != "" {
		if s != "message" {
			t.Errorf("%s: event_received = %q, want \"message\"", vectorID, s)
		}
	}
}

func dispatchKnownIdentity(t *testing.T, vectorID string, input, expected map[string]any) {
	t.Helper()
	if _, ok := expected["identity_key_known"]; ok {
		assertBoolFieldTrue(t, vectorID, "identity_key_known", expected)
	}
	if v, ok := expected["persists_for"]; ok && v != "connection lifetime" {
		t.Errorf("%s: persists_for = %v, want \"connection lifetime\"", vectorID, v)
	}
	key, _ := input["expected_identity_key"].(string)
	if !pubKeyHexPattern.MatchString(key) {
		t.Errorf("%s: expected_identity_key %q does not match pubkey pattern", vectorID, key)
	}
}
