package auth_test

import (
	"encoding/json"
	"regexp"
	"testing"
)

// pubKeyHexPattern matches the BRC-103 canonical compressed public key
// format asserted throughout the corpus (auth.brc31-handshake.15,
// messaging.authsocket.12, ...): 66 hex chars, prefix 02 or 03.
var pubKeyHexPattern = regexp.MustCompile(`^0[23][0-9a-fA-F]{64}$`)

// base64Pattern mirrors the TS dispatcher's BASE64_PATTERN
// (conformance/runner/ts/dispatchers/auth.ts): a loose base64-alphabet
// shape check, independent of the stricter canonical/length checks done
// elsewhere.
var base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)

func assertBase64Pattern(t *testing.T, vectorID, field, s string) {
	t.Helper()
	if !base64Pattern.MatchString(s) {
		t.Errorf("%s: %s %q does not match the base64 pattern", vectorID, field, s)
	}
}

// decodeGenericObject decodes a vector's raw Input/Expected JSON into a
// generic map, the same loosely-typed shape the TS dispatchers operate on
// (Record<string, unknown>). Vector shapes vary by row, so typed structs
// would need almost as many variants as there are vectors.
func decodeGenericObject(t *testing.T, vectorID string, raw json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("%s: decode object: %v", vectorID, err)
	}
	return m
}

func getBoolField(m map[string]any, key string) bool {
	v, ok := m[key].(bool)
	return ok && v
}

func assertBoolFieldTrue(t *testing.T, vectorID, key string, m map[string]any) {
	t.Helper()
	got, ok := m[key].(bool)
	if !ok || !got {
		t.Errorf("%s: %s = %v, want true", vectorID, key, m[key])
	}
}

func assertStringFieldEquals(t *testing.T, vectorID, key string, m map[string]any, want string) {
	t.Helper()
	got, ok := m[key].(string)
	if !ok || got != want {
		t.Errorf("%s: %s = %v, want %q", vectorID, key, m[key], want)
	}
}

func toStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, el := range arr {
		s, ok := el.(string)
		if !ok {
			return nil
		}
		out = append(out, s)
	}
	return out
}
