package overlay

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProtocolID_SHIP(t *testing.T) {
	got := ProtocolSHIP.ID()
	require.Equal(t, ProtocolIDSHIP, got)
	require.Equal(t, ProtocolID("service host interconnect"), got)
}

func TestProtocolID_SLAP(t *testing.T) {
	got := ProtocolSLAP.ID()
	require.Equal(t, ProtocolIDSLAP, got)
	require.Equal(t, ProtocolID("service lookup availability"), got)
}

func TestProtocolID_Unknown(t *testing.T) {
	got := Protocol("UNKNOWN").ID()
	require.Equal(t, ProtocolID(""), got)
}

func TestProtocolID_Empty(t *testing.T) {
	got := Protocol("").ID()
	require.Equal(t, ProtocolID(""), got)
}

func TestProtocol_AllCases(t *testing.T) {
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
