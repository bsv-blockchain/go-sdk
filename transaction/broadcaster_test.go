package transaction

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBroadcastFailureJSONShape pins the wire shape of BroadcastFailure to
// ts-sdk's BroadcastFailure: { code, description, more?: { competingTxs } }.
// competingTxs must be nested under "more", not a top-level field, even
// though the Go struct keeps CompetingTxs as an ergonomic top-level field.
func TestBroadcastFailureJSONShape(t *testing.T) {
	t.Run("without competing txs omits more", func(t *testing.T) {
		failure := &BroadcastFailure{Code: "REJECTED", Description: "REJECTED bad script"}
		b, err := json.Marshal(failure)
		require.NoError(t, err)

		var raw map[string]any
		require.NoError(t, json.Unmarshal(b, &raw))
		require.Equal(t, "REJECTED", raw["code"])
		require.Equal(t, "REJECTED bad script", raw["description"])
		_, hasMore := raw["more"]
		require.False(t, hasMore, "more must be omitted when there are no competing txs")
		_, hasTopLevel := raw["competingTxs"]
		require.False(t, hasTopLevel, "competingTxs must never be a top-level JSON field")
	})

	t.Run("with competing txs nests under more", func(t *testing.T) {
		failure := &BroadcastFailure{
			Code:         "DOUBLE_SPEND_ATTEMPTED",
			Description:  "DOUBLE_SPEND_ATTEMPTED competing tx: deadbeef",
			CompetingTxs: []string{"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"},
		}
		b, err := json.Marshal(failure)
		require.NoError(t, err)

		var raw map[string]any
		require.NoError(t, json.Unmarshal(b, &raw))
		_, hasTopLevel := raw["competingTxs"]
		require.False(t, hasTopLevel, "competingTxs must be nested under more, not top-level")
		more, ok := raw["more"].(map[string]any)
		require.True(t, ok, "more must be an object when competing txs are present")
		competing, ok := more["competingTxs"].([]any)
		require.True(t, ok)
		require.Equal(t, []any{"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}, competing)

		// Round-trips back through UnmarshalJSON.
		var decoded BroadcastFailure
		require.NoError(t, json.Unmarshal(b, &decoded))
		require.Equal(t, failure.Code, decoded.Code)
		require.Equal(t, failure.Description, decoded.Description)
		require.Equal(t, failure.CompetingTxs, decoded.CompetingTxs)
	})

	t.Run("unmarshal from ts-sdk shaped payload", func(t *testing.T) {
		wire := `{"code":"DOUBLE_SPEND_ATTEMPTED","description":"DOUBLE_SPEND_ATTEMPTED competing tx: deadbeef","more":{"competingTxs":["deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"]}}`
		var decoded BroadcastFailure
		require.NoError(t, json.Unmarshal([]byte(wire), &decoded))
		require.Equal(t, "DOUBLE_SPEND_ATTEMPTED", decoded.Code)
		require.Equal(t, []string{"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}, decoded.CompetingTxs)
	})
}

// TestBroadcastFailureErrorAfterJSONRoundTrip checks the error interface is
// unaffected by the custom JSON (un)marshaling methods.
func TestBroadcastFailureErrorAfterJSONRoundTrip(t *testing.T) {
	failure := &BroadcastFailure{Code: "500", Description: "boom"}
	b, err := json.Marshal(failure)
	require.NoError(t, err)

	var decoded BroadcastFailure
	require.NoError(t, json.Unmarshal(b, &decoded))

	var asErr error = &decoded
	require.EqualError(t, asErr, "boom")
}
