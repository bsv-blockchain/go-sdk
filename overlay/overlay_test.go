package overlay

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
