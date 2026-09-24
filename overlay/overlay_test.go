package overlay

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAdmittanceInstructionsWireShape locks in the lowercase/camelCase JSON
// keys the TypeScript reference SDK's STEAK type expects
// (outputsToAdmit/coinsToRetain/coinsRemoved). Without explicit struct tags,
// Go's default field-name marshaling would emit PascalCase keys that a
// strict TS client rejects as unexpected instruction fields.
func TestAdmittanceInstructionsWireShape(t *testing.T) {
	instructions := &AdmittanceInstructions{
		OutputsToAdmit: []uint32{0, 2},
		CoinsToRetain:  []uint32{1},
		CoinsRemoved:   []uint32{3},
	}

	data, err := json.Marshal(instructions)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))

	require.Contains(t, decoded, "outputsToAdmit")
	require.Contains(t, decoded, "coinsToRetain")
	require.Contains(t, decoded, "coinsRemoved")
	require.NotContains(t, decoded, "OutputsToAdmit")
	require.NotContains(t, decoded, "CoinsToRetain")
	require.NotContains(t, decoded, "CoinsRemoved")
}

// TestAdmittanceInstructionsOmitsOptionalFields confirms coinsRemoved and
// ancillaryTxids (both optional/Go-only extensions) are omitted rather than
// emitted as null when unset, keeping output minimal like the reference type.
func TestAdmittanceInstructionsOmitsOptionalFields(t *testing.T) {
	instructions := &AdmittanceInstructions{OutputsToAdmit: []uint32{0}}

	data, err := json.Marshal(instructions)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))

	require.NotContains(t, decoded, "coinsRemoved")
	require.NotContains(t, decoded, "ancillaryTxids")
}

// TestAdmittanceInstructionsDecodesLowercaseWire confirms decoding a real
// STEAK response (lowercase keys, as an overlay server actually sends) still
// populates the Go struct correctly.
func TestAdmittanceInstructionsDecodesLowercaseWire(t *testing.T) {
	var instructions AdmittanceInstructions
	require.NoError(t, json.Unmarshal([]byte(`{"outputsToAdmit":[0,1],"coinsToRetain":[2],"coinsRemoved":[3]}`), &instructions))

	require.Equal(t, []uint32{0, 1}, instructions.OutputsToAdmit)
	require.Equal(t, []uint32{2}, instructions.CoinsToRetain)
	require.Equal(t, []uint32{3}, instructions.CoinsRemoved)
}

func TestProtocolIDSHIP(t *testing.T) {
	got := ProtocolSHIP.ID()
	require.Equal(t, ProtocolIDSHIP, got)
	require.Equal(t, ProtocolID("service host interconnect"), got)
}

func TestProtocolIDSLAP(t *testing.T) {
	got := ProtocolSLAP.ID()
	require.Equal(t, ProtocolIDSLAP, got)
	require.Equal(t, ProtocolID("service lookup availability"), got)
}

func TestProtocolIDUnknown(t *testing.T) {
	got := Protocol("UNKNOWN").ID()
	require.Equal(t, ProtocolID(""), got)
}

func TestProtocolIDEmpty(t *testing.T) {
	got := Protocol("").ID()
	require.Equal(t, ProtocolID(""), got)
}

func TestProtocolAllCases(t *testing.T) {
	tests := []struct {
		name     string
		protocol Protocol
		expected ProtocolID
	}{
		{"SHIP", ProtocolSHIP, ProtocolIDSHIP},
		{"SLAP", ProtocolSLAP, ProtocolIDSLAP},
		{"unknown string", Protocol("OTHER"), ProtocolID("")},
		{"empty string", Protocol(""), ProtocolID("")},
		{"lowercase ship", Protocol("ship"), ProtocolID("")},
		{"lowercase slap", Protocol("slap"), ProtocolID("")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.protocol.ID()
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestNetworkNames(t *testing.T) {
	require.Equal(t, "mainnet", NetworkNames[NetworkMainnet])
	require.Equal(t, "testnet", NetworkNames[NetworkTestnet])
	require.Equal(t, "local", NetworkNames[NetworkLocal])
}
